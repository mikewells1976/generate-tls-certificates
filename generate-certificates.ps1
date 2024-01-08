# We have to run as administrator
#Requires -RunAsAdministrator

# Class that holds RootCA paths
class RootCA {
    [string]$PathCRT
    [string]$PathKey

    RootCA([string]$rootCAcrt, [string]$rootCAkey) {
        $this.PathCRT = $rootCAcrt
        $this.PathKey = $rootCAkey
    }
}

# Class that holds defined configuration
class Config {

    Config() {
    }

    # Asking database type and verify
    [string] GetDatabase() {
    	$databaseInput = Read-Host "Which database are you generating certificates for? [Default: Cassandra, Options: Cassandra|Elastic|OpenSearch]"
	    if($databaseInput -eq ""){
		    $databaseInput = "Cassandra"
	    }
	    if($databaseInput -notin @("Cassandra","Elastic","OpenSearch")){
		    Write-Host -ForegroundColor red "Invalid input: Database should be either Cassandra, Elastic or OpenSearch"
		    exit 1
	    }

        return $databaseInput
    }

    # Asking for clustername and verify
    [string] GetClusterName() {
        $clusterName = Read-Host "Please enter the name of your cluster: [Default: DMS]"
        if ($clusterName -eq "") {
            $clusterName = "DMS"
        }
        if ($clusterName -cmatch "[^\x00-\x7F]") {
            Write-Host -ForegroundColor yellow "Warning: Your clustername contains non-ascii characters. This may prevent your nodes from starting up if you have internode encryption turned on."
            Write-Host -ForegroundColor yellow "Do you want to proceed? (May cause your cluster to fail to start) [Default: n, Options y|n]"
            $Proceed = Read-Host
            if ($Proceed -ine "y") {
                Write-Host "Quitting..."
                Exit 2
            }
        }

        return $clusterName
    }

    # Asking for validity and verify
    [string] GetValidaty() {
    	$validityInput = Read-Host "How long (days) should the certificates remain valid? [Default: 365 days, Min: 30, Max: 3650]"
	    if($validityInput -eq ""){
		    $validityInput = "365"
	    }

	    # Check if integer
	    $validityInput = $validityInput -as [int]
	    if($validityInput -eq $null){
		    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be an integer (days)"
		    Exit 3
	    }

        # Check if between min and max
	    if($validityInput -lt 30 -or $validityInput -gt 3650){
		    Write-Host -ForegroundColor red "Invalid input: Certificate validity should be between 30 and 3650 days"
		    Exit 4
	    }

        return $validityInput
    }

    # Asking keysize
    [string] GetKeySize() {
	    $keysizeInput = Read-Host "How long (bit) should the certificate key size be? [Default: 4096 bit, Options: 1024|2048|4096|8192]"
	    if($keysizeInput -eq ""){
		    $keysizeInput = "4096"
	    }
	    # check if keysize is one of the options
	    if($keysizeInput -notin @("1024","2048","4096","8192")){
		    Write-Host -ForegroundColor red "Invalid input: Key size should be of size 1024, 2048, 4096 or 8192 bit"
		    exit 5
	    }
		
		return $keysizeInput
    }

    # Asking HostNames
    [string] GetHostNames() {
		$hostNames = @()

			while ($true) {
				$inputString = Read-Host "Please enter the hostnames (FQDN) of every node (space separated)"
				$hostNames = $inputString -split " " -ne ''  # Remove empty elements
				
				if ($hostNames.Count -eq 0) {
					Write-Host -ForegroundColor red "Invalid input: No hostnames were provided, please provide at least one hostname."
				} else {
					break
				}
			}

		return $hostNames
    }

    # Ask if hostnames need to be resolved
    [string] AskResolveHostName() {
        $resolveHostNameInput = Read-Host "Do you want me to try to resolve the hostnames automatically instead of manually entering the IP addresses for every node? [Default: y, Options: y|n]"
        return $resolveHostNameInput
    }
}

# Function to prompt for a valid path
function Get-ValidPath {
    param(
		[string]$defaultPath,
        [string]$file,
        [string]$tooltip
    )
    
    $path = $defaultPath
    while (-not (Test-Path $path -PathType Leaf)) {
        Write-Host $tooltip
        $path = Read-Host "Please enter the absolute path to the $file"
		if(-not $path -Contains $file){
			 $path = Read-Host "Please enter the absolute path to the $file"
		}
    }
    return $path
}

# Function to clean up the working directory
function Clean-WorkingDirectory {
    param()
    
    $Clean = Read-Host "Do you want to remove previously generated certificates/truststores from the current directory? [Default=y, Option y|n]"
    if ($Clean -ine "n") {
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
}

# Function to generate a new Root Certificate using OpenSSL tool
function Create-New-RootCA{
	param()
	
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
}

# Function to generate root certificate
function Generate-RootCertificate {
    param(
        [string]$database,
        [string]$clusterName,
        [int]$validity,
        [int]$keySize,
        [string]$password
    )

    $useExisting = Read-Host "Do you want to use an existing root certificate? [Default=y, Option y|n]"
	if ($useExisting -ine "n") {
        $rootCAcrt =  Get-ValidPath -defaultPath "C:\absolute\path\to\rootCA.crt" -file "rootCA.crt" -tooltip $null
		$rootCAkey =  Get-ValidPath -defaultPath "C:\absolute\path\to\rootCA.key" -file "rootCA.key" -tooltip $null
        return [RootCA]::new($rootCAcrt, $rootCAkey)
	}else{
		Create-New-RootCA
        return [RootCA]::new("*rootCA.crt", "rootCA.key")
	}
}

# Function to generate node certificates
function Generate-NodeCertificates {
    param(
        [array]$hostNames,
        [string]$resolveHostName,
        [string]$password,
        [string]$rootCAcrt,
        [string]$rootCAkey
    )

    foreach ($i in $HostNames) {
		Write-Host "Generating certificate for node: $i"
		 $NodeIP = ""
			# check if we need to resolve the hostname
			if($ResolveHostName -ine "n"){
				Write-Host "Resolving $i to IP..."
				try {
					$ResIp = Resolve-DnsName -Name $i -ErrorAction Stop |  Select -ExpandProperty "IpAddress" | Out-String
					$ResIp = $ResIp.Trim()
					if( ($ResIp -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') -and ($ResIp -ne '127.0.0.1') ){
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
		   & "$openssl" "x509" "-req" "-CA" $rootCAcrt "-CAkey" $rootCAkey "-in" "$i.csr" "-out" "$i.crt_signed" "-days" "$Validity" "-CAcreateserial" "-passin" "pass:$Password" "-extfile" "$i.conf"

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
}

# Function to add public keys to keystore of every other node
function Add-PublicKeysToKeystore {
    param(
        [array]$hostNames,
        [string]$password
    )

    if ($HostNames.Length -ge 2) {
        Write-Host "Adding the public key of every node to every other node..."
        foreach ($i in $HostNames) {
            foreach ($j in $HostNames) {
                if ($i -ceq $j) {
                    continue
                }

                & "$keytool" "-keystore" "$i-node-keystore.p12" "-alias" "$j" "-importcert" "-file" "$j-public-key.cer" "-keypass" "$Password" "-storepass" "$Password" "-noprompt"
            }
        }
    }
}

# Function to clean up and provide final instructions
function Clean-Up-And-Instructions {
    param(
        [string]$password,
        [string]$rootCAcrt,
        [string]$rootCAkey
    )

	Remove-Item "*.crt_signed"
	Remove-Item "*.csr"
	Remove-Item "*.conf"
	Remove-Item "*.srl"
	# Remove line below for debugging with devcenter
	Remove-Item "*.jks"

	Write-Host 
	Write-Host -ForegroundColor Green "Copy the following certificates to every client:"
	Get-ChildItem -File $rootCAcrt | foreach-object { Write-Host "> $_"}

	Write-Host
	Write-Host -ForeGroundColor Green "Copy the following keystores to the matching node:"
	Get-ChildItem -File "*-node-keystore.p12" | foreach-object { Write-Host "> $_"}

	Write-Host
	Write-Host -ForeGroundColor Green "Keep the following files PRIVATE:"
	Get-ChildItem -File $rootCAkey | foreach-object { Write-Host "> $_"}

	if($password -ine $null){
		Write-Host
		Write-Host -ForeGroundColor Green "The generated password is: $password"
	}
}

# Function to log the configuration details
function Log-ConfigurationDetails {
    param(
        [string]$database,
        [string]$clusterNames,
        [string]$hostNames,
        [string]$validity,
        [string]$keysize,
        [string]$resolveHostName
    )

    Write-Host "---- Generating Node(s) Certificates ----"
    Write-Host "Database type: $Database"
    Write-Host "Cluster name: $ClusterNames"
    Write-Host "Host names: $HostNames"
    Write-Host "Validity: $Validity"
    Write-Host "Keysize: $Keysize"
    Write-Host "Resolve hostnames? $ResolveHostName"
}

# Function to generate secure certificate password
function Generate-Password {
    $Password = $null
    
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

    return $Password
}

# Main Function
function Main{
    # Get executables phase
	$keytool = Get-ValidPath -defaultPath "C:\absolute\path\to\keytool.exe" -file "keytool.exe" -tooltip "It is recommended to use the keytool executable provided with cassandra/elastic/opensearch."
	$openssl = Get-ValidPath -defaultPath "C:\absolute\path\to\openssl.exe" -file "openssl.exe" -tooltip $null

    # Cleanup phase
	Write-Host
	Clean-WorkingDirectory

	# Configuration phase
	Write-Host "Starting Cassandra/Elastic/OpenSearch TLS encryption configuration..."
    $config = [Config]::new()
    $Database = $config.GetDatabase()
    $ClusterName = $config.GetClusterName()
    $Hostnames = $config.GetHostNames()
    $Validity = $config.GetValidaty()
    $Keysize = $config.GetKeySize()
    $ResolveHostName = $config.AskResolveHostName()

    # Password generation phase
    $Password = Generate-Password

    # Certificates phase
    Log-ConfigurationDetails -database $Database -clusterNames $ClusterName -hostNames $Hostnames -validity $Validity -keysize $Keysize -resolveHostName $ResolveHostName
	$rootCA = Generate-RootCertificate -database $Database -clusterName $ClusterName -validity $Validity -keySize $Keysize -password $Password
	Generate-NodeCertificates -hostNames $HostNames -resolveHostName $ResolveHostName -password $Password -rootCAcrt $rootCA.PathCRT -rootCAkey $rootCA.PathKey
	Add-PublicKeysToKeystore -hostNames $HostNames -password $Password
	Clean-Up-And-Instructions -password $Password -rootCAcrt $rootCA.PathCRT -rootCAkey $rootCA.PathKey
}

Main
Write-Host "Script complete"
exit 0