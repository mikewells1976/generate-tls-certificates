# We have to run as administrator
#Requires -RunAsAdministrator

#
# Keytool and OpenSSL executable paths
# You can configure them in the script or at run time
#
# I recommend to use the keytool that is provided with cassandra/elastic/opensearch (e.g. cassandra/java/bin/keytool.exe)
# Using a keytool from a different java version then the one included may result in an 'Invalid Keystore format' error
#
$keytool = "c:\absolute\path\to\keytool.exe"
while(-not (Test-Path $keytool -PathType Leaf)){
    Write-Host "No valid keytool.exe is configured."
    Write-Host "It is recommended to use the keytool executable provided with cassandra/elastic/opensearch."
    Write-Host "Using a keytool executable from a different java version the the one included with cassandra/elastic/opensearch may result in an 'Invalid Keystore format error'"
    $keytool = Read-Host "Please enter the absolute path to the keytool executable"
}

$openssl = "c:\absolute\path\to\openssl.exe"
while(-not (Test-Path $openssl -PathType Leaf)){
    Write-Host "No valid openssl.exe is configured."
    $openssl = Read-Host "Please enter the absolute path to the openssl executable"
}
Write-Host

#
# Cleaning up the working directory, if wanted
#
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
	Remove-Item "*.p12"
}

# 
# Configuration phase
#
Write-Host "Starting Cassandra/Elastic/OpenSearch TLS encryption configuration..."

# Asking database type and verify
$Database = Read-Host "Which database are you generating certificates for? [Default: Cassandra, Options: Cassandra|Elastic|OpenSearch]"
if($Database -eq ""){
    $Database = "Cassandra"
}
if($Database -notin @("Cassandra","Elastic","OpenSearch")){
    Write-Host -ForegroundColor red "Invalid input: Database should be either Cassandra, Elastic or OpenSearch"
    exit 1
}

# Asking for clustername and verify
$ClusterName = Read-Host "Please enter the name of your cluster: [Default: DMS]"
if($ClusterName -eq ""){
    $ClusterName = "DMS"
}
# Check for non ascii characters, this can cause trouble for internode encryption
if($ClusterName -cmatch "[^\x00-\x7F]"){
    Write-Host -ForegroundColor yellow "Warning: Your clustername contains non ascii characters. This may prevent your nodes from starting up if you have internode encryption turned on."
    Write-Host -ForegroundColor yellow "Do you want to proceed? (May cause your cluster to fail to start) [Default: n, Options y|n]"
    $Proceed = Read-Host
    if($Proceed -ine "y"){
        Write-Host "Quiting..."
        Exit 2
    }
}

# Asking for validity and verify
$Validity = Read-Host "How long (days) should the certificates remain valid? [Default: 365 days, Min: 30, Max: 3650]"
if($Validity -eq ""){
    $Validity = "365"
}
# check if integer
$Validity = $Validity -as [int]
if($Validity -eq $null){
    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be an integer (days)"
    Exit 3
}
# check if between min and max
if($Validity -lt 30 -or $Validity -gt 3650){
    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be between 30 and 3650 days"
    Exit 4
}


$Keysize = Read-Host "How long (bit) should the certificate key size be? [Default: 4096 bit, Options: 1024|2048|4096|8192]"
if($Keysize -eq ""){
    $Keysize = "4096"
}
# check if keysize is one of the options
if($Keysize -notin @("1024","2048","4096","8192")){
    Write-Host -ForegroundColor red "Invalid input: Key size should be of size 1024, 2048, 4096 or 8192 bit"
    exit 5
}

# Asking for hostnames
$HostNames = Read-Host "Please enter the hostnames (FQDN) of every node (space separated)"
$HostNames = $HostNames -split " "
if($HostNames.Length -eq 0){
    Write-Host -ForegroundColor red "Invalid input: No hostnames were provided, please provide at least one hostname."
    exit 6
}
# Ask if hostnames need to be resolved
$ResolveHostName = Read-Host "Do you want me to try to resolve the hostnames automatically instead of manually entering the IP addresses for every node? [Default: y, Options: y|n]"

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
Write-Host "Database type: $Database"
Write-Host "Cluster name: $ClusterNames"
Write-Host "Host names: $HostNames"
Write-Host "Validity: $Validity"
Write-Host "Keysize: $Keysize"
Write-Host "Resolve hostnames? $ResolveHostName"

#
# Root certificate generation
#
Write-Host "Generating the root certificate"
"[ req ]
distinguished_name  = req_distinguished_name
prompt              = no
output_password     = `"$Password`"
default_bits        = $KeySize

[ req_distinguished_name ]
C     = BE
O     = $Database
CN    = rootCA
OU    = `"$ClusterName`"" | Out-File -Encoding "UTF8" rootCA.conf

# Create a new Root CA certificate and store the private key in rootCA.key, public key in rootCA.crt
& "$openssl" "req" "-config" "rootCA.conf" "-new" "-x509" "-nodes" "-keyout" "rootCA.key" "-out" "rootCA.crt" "-days" "$Validity"

#
# Node certificates generation
#
foreach($i in $HostNames){
    Write-Host "Generating certificate for node: $i"
    $NodeIP = ""
    # check if we need to resolve the hostname
    if($ResolveHostName -ine "n"){
        Write-Host "Resolving $i to IP..."
        try {
            $ResIp = Resolve-DnsName -Name $i -ErrorAction Stop |  Select -ExpandProperty "IpAddress" | Out-String
            $ResIp = $ResIp.Trim()
            if($ResIp -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'){
                Write-Host -ForeGroundColor Green "Resolved $i to IP: $ResIp"
                $NodeIP = $ResIp
            }
            else {
                Write-Host "Could not resolve the hostname to a single IP. I found the following IPs:"
                Write-Host -ForegroundColor Green $ResIp
            }
        }
        catch {
            Write-Host -ForeGroundColor Yellow "Failed to resolve $i to a valid IP."
        }
    }

    # check if hostname was resolved
    if($NodeIP -eq ""){
        # Hostname was not resolved, ask for IP
        $NodeIP = Read-Host "Please enter the IP address for node $i"
    }

   # Importing the public Root CA certificate in node keystore
   Write-Host "Importing Root CA certificate in node keystore"
   & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "rootCA" "-importcert" "-file" "rootCA.crt" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"

   Write-Host "Generating new key pair for node: $i"
   & "$keytool" "-genkeypair" "-keyalg" "RSA" "-alias" "$i" "-keystore" "$i-node-keystore.jks" "-storepass" "$Password" "-keypass" "$Password" "-validity" "$Validity" "-keysize" "$keySize" "-dname" "CN=$i, OU=$clusterName, O=$Database, C=BE" "-ext" "san=ip:$nodeIp,dns:$i"

   Write-Host "Creating signing request"
   & "$keytool" "-keystore" "$i-node-keystore.jks" "-alias" "$i" "-certreq" "-file" "$i.csr" "-keypass" "$Password" "-storepass" "$Password" 

   # Add both hostname and IP as subject alternative name, write this configuration to a temp file
   "subjectAltName=DNS:$i,IP:$NodeIP" | Out-File -Encoding "UTF8" "${i}.conf"

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
   
   # Convert to PKCS#12, usable for ElasticSearch/OpenSearch
   Write-Host "Creating PKCS#12 from JKS for $i"
   & "$keytool" "-importkeystore" "-srckeystore" "$i-node-keystore.jks" "-destkeystore" "$i-node-keystore.p12" "-srcstoretype" "JKS" "-deststoretype" "PKCS12" "-srcstorepass" "$Password" "-deststorepass" "$Password"
   
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

            & "$keytool" "-keystore" "$i-node-keystore.p12" "-alias" "$j" "-importcert" "-file" "$j-public-key.cer" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"
        }

        # Debugging
        # & "$keytool" "-list" "-keystore" "$i-node-keystore.p12" "-storepass" "$Password"
    }
}

#
# Finished, now clean up and write final instrucitons
#
Remove-Item "*.crt_signed"
Remove-Item "*.csr"
Remove-Item "*.conf"
Remove-Item "*.srl"
# Remove line below for debugging with devcenter
Remove-Item "*.jks"

Write-Host 
Write-Host -ForegroundColor Green "Copy the following certificates to every client:"
Get-ChildItem -File "*rootCA.crt" | foreach-object { Write-Host "> $_"}

Write-Host
Write-Host -ForeGroundColor Green "Copy the following keystores to the matching node:"
Get-ChildItem -File "*-node-keystore.jks" | foreach-object { Write-Host "> $_"}

Write-Host
Write-Host -ForeGroundColor Green "Keep the following files PRIVATE:"
Get-ChildItem -File "rootCA.key" | foreach-object { Write-Host "> $_"}

if($GeneratePassword -ine "n"){
    Write-Host
    Write-Host -ForeGroundColor Green "The generated password is: $Password"
}

Write-Host
Write-Host "Script complete"
exit 0
