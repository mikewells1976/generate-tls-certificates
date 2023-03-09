# We have to run as administrator
#-Requires -RunAsAdministrator

#
# Keytool and OpenSSL executable paths
# I recommend to use the keytool that is provided with cassandra (cassandra/java/bin/keytool.exe)
# Using a keytool from a different java version then the one included in cassandra may result in an 'Invalid Keystore format' error
#
$keytool = "path\to\keytool.exe"
$openssl = "path\to\openssl.exe"


# Cleaning up the working directory
$Clean = Read-Host "Do you want to remove previously generated certificates/truststores from the current directory? [Default=y, Option y|n]"
if($Clean -ine "n"){
    Remove-Item "*.crt_signed"
    Remove-Item "*.crt"
    Remove-Item "*.key"
    Remove-Item "*.csr"
    Remove-Item "*.cer"
    Remove-Item "*.jks"
    Remove-Item "*.conf"
    Remove-Item "*.srl"
}




Write-Host "Starting Cassandra TLS encryption configuration..."

$ClusterName = Read-Host "Please enter the name of your Cassandra cluster: [Default: DMS]"
if($ClusterName -eq ""){
    $ClusterName = "DMS"
}
# Check for non ascii characters, this can cause trouble for internode encryption
if($ClusterName -cmatch "[^\x00-\x7F]"){
    Write-Host -ForegroundColor yellow "Warning: Your clustername contains non ascii characters. This may prevent your nodes from starting up if you have internode encryption turned on."
    Write-Host -ForegroundColor yellow "Do you want to proceed? (May cause your Cassandra cluster to fail to start) [Default: n, Options y|n]"
    $Proceed = Read-Host
    if($Proceed -ine "y"){
        Write-Host "Quiting..."
        Exit 1
    }
}


$Validity = Read-Host "How long (days) should the certificates remain valid? [Default: 365 days, Min: 30, Max: 3650]"
if($Validity -eq ""){
    $Validity = "365"
}
# check if integer
$Validity = $Validity -as [int]
if($Validity -eq $null){
    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be an integer (days)"
    Exit 2
}
# check if between min and max
if($Validity -lt 30 -or $Validity -gt 3650){
    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be between 30 and 3650 days"
    Exit 3
}


$Keysize = Read-Host "How long (bit) should the certificate key size be? [Default: 2048 bit, Options: 1024|2048|4096|8192]"
if($Keysize -eq ""){
    $Keysize = "2048"
}
# check if keysize is one of the options
if($Keysize -notin @("1024","2048","4096","8192")){
    Write-Host -ForegroundColor red "Invalid input: Key size should be of size 1024, 2048, 4096 or 8192 bit"
    exit 4
}


$HostNames = Read-Host "Please enter the hostnames (FQDN) of every Cassandra node (space separated)"
$HostNames = $HostNames -split " "

$GeneratePassword = Read-Host "Do you want me to automatically generate a secure certificate password (instead of manually entering one)? [Default: y, Options: y|n]"
if($GeneratePassword -ine "n"){
    $Password = & "$openssl" "rand" "-hex" "20"
    Write-Host "Generated password is: $Password"
}
else {
    $Password = Read-Host "Please enter a password for the certificates and truststores [Min length: 10]"
    $Confirmation = Read-Host "Please re-enter the password"
    While($Password -cne $Confirmation -or $Password.Length -lt 10){
        Write-Host "The passwords did not match or it is shorter then 10 characters"
        $Password = Read-Host "Please enter a password for the certificates and truststores"
        $Confirmation = Read-Host "Please re-enter the password"
    }
}

# Log the configuration details
Write-Host "---- Generating Certificates ----"
Write-Host "Cluster name: $ClusterNames"
Write-Host "Host names: $HostNames"
Write-Host "Validity: $Validity"
Write-Host "Keysize: $Keysize"

# Start Generating root certificate
Write-Host "Generating the root certificate"
"[ req ]
distinguished_name  = req_distinguished_name
prompt              = no
output_password     = $Password
default_bits        = $KeySize

[ req_distinguished_name ]
C     = BE
O     = Cassandra
CN    = rootCA
OU    = $ClusterName" | Out-File -Encoding "UTF8" rootCA.conf

# Create a new Root CA certificate and store the private key in rootCA.key, public key in rootCA.crt
& "$openssl" "req" "-config" "rootCA.conf" "-new" "-x509" "-nodes" "-keyout" "rootCA.key" "-out" "rootCA.crt" "-days" "$Validity"

# Create a certificate for every node
foreach($i in $HostNames){
    Write-Host "Generating certificate for node: $i"
    $NodeIP = Read-Host "Please enter the IP address for node $i"

   # Importing the public Root CA certificate in node keystore
   Write-Host "Importing Root CA certificate in node keystore"
   & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "rootCA" "-importcert" "-file" "rootCA.crt" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"

   Write-Host "Generating new key pair for node: $i"
   & "$keytool" "-genkeypair" "-keyalg" "RSA" "-alias" "$i" "-keystore" "$i-node-keystore.jks" "-storepass" "$Password" "-keypass" "$Password" "-validity" "$Validity" "-keysize" "$keySize" "-dname" "CN=$i, OU=$clusterName, O=Cassandra, C=BE" "-ext" "san=ip:$nodeIp"

   Write-Host "Creating signing request"
   & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "$i" "-certreq" "-file" "$i.csr" "-keypass" "$Password" "-storepass" "$Password"

   # Add both hostname and IP as subject alternative name, write this configuration to a temp file
   "subjectAltName=DNS:$i,IP:$NodeIp" | Out-File -Encoding "UTF8" "$i.conf"

   # Sign the node certificate with the private key of the rootCA
   Write-Host "Signing certificate with Root CA certificate"
   & "$openssl" "x509" "-req" "-CA" "rootCA.crt" "-CAkey" "rootCA.key" "-in" "$i.csr" "-out" "$i.crt_signed" "-days" "$Validity" "-CAcreateserial" "-passin" "pass:$Password" "-extfile" "$i.conf"

   # Import the signed certificate in the node key store
   Write-Host "Importing signed certificate for $i in node keystore"
   & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "$i" "-importcert" "-file" "$i.crt_signed" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"

   # Export the public key for every node
   Write-Host "Exporting public key for $i"
   & "$keytool" "-exportcert" "-alias" "$i" "-keystore" "$i-node-keystore.jks" "-file" "$i-public-key.cer" "-storepass" "$Password"

   # Log the certificates for this node (for debugging purposes)
   #Write-Host "Certificates in node-keystore for $i:"
   #& "$keytool -list -keystore $i-node-keystore.jks -storepass $Password"

   # Debugging: Create keystore with public cert (mostly for CQL clients DevCenter)
   # Write-Host "Creating public truststore for clients"
   # & "$keytool" "-keystore" "$i-public-truststore.jks" "-alias" "$i" "-importcert" "-file" "$i-public-key.cer" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"

   Write-Host "Finished for $i"
}

# Add the public key of every node to the keystore of every other node (when there are multiple nodes)
if($HostNames.Length -ge 2){
    Write-Host "Adding the public key of every node to every other node..."
    foreach($i in $HostNames){
        foreach($j in $HostNames){
            if($i -ceq $j){
                continue
            }

            & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "$j" "-importcert" "-file" "$j-public-key.cer" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"
        }

        # For debugging
        # & "$keytool" "-list" "-keystore" "$i-node-keystore.jks" "-storepass" "$Password"
    }
}

Write-Host 
Write-Host -ForegroundColor Green "Copy the following certificates to every Cassandra client:"
Get-ChildItem -File "*rootCA.crt" | foreach-object { Write-Host "> $_"}

Write-Host
Write-Host -ForeGroundColor Green "Copy the following keystores to the matching Cassandra node:"
Get-ChildItem -File "*-node-keystore.jks" | foreach-object { Write-Host "> $_"}

Write-Host
Write-Host -ForeGroundColor Green "Keep the following files PRIVATE:"
Get-ChildItem -File "rootCA.key" | foreach-object { Write-Host "> $_"}

Write-Host


