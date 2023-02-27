#!/bin/bash
# Run this script like: bash <filename>.sh

# Verify we are running with superuser privileges
if [[ $(id -u) != 0 ]]; then
    echo 'Permission Denied: Please run this script with superuser privileges.'
    exit 1
fi

# output formatting variables
YELLOW="\033[1;33m"
RED="\033[31m"
NC="\033[0m"

echo 'Starting Cassandra TLS encryption configuration...'

read -p 'Please enter the name of your Cassandra cluster: [Default: DMS] ' clusterName

# Check if the provided clustername contains non-ASCII/special characters
if [[ $(grep -P "[\x80-\xFF]" <<< $clusterName) ]]; then
   # A non ascii character was found
   echo -e "${RED}Warning:${NC} Your clustername contains non ascii characters. This may prevent your nodes from starting up if you have internode encryption turned on."
   read -p "Do you want to proceed? (May cause your Cassandra cluster to fail to start) [Default: n, Options y|n] " proceed
   proceed=${proceed:n}
   if [[ $proceed != "y" ]]; then
      echo "Quiting..."
      exit 2
   fi
fi

read -p 'How long (days) should the certificates remain valid? [Default: 365 days, Min: 30, Max: 3650]? ' validity
read -p 'How long (bit) should the certificate key size be? [Default: 2048 bit, Options: 1024|2048|4096|8192]? ' keySize

echo 'Please enter the hostnames (FQDN) of every Cassandra node (space separated): '
read -a hostNames

read -p 'Do you want me to resolve the hostnames automatically instead of manually entering the IP addresses for every node? [y|n] ' resolveHostName
read -p "Do you want me to automatically generate a secure certificate password (instead of manually entering one)? [y|n] " generatePwd

# Set default values
validity=${validity:-365}
clusterName=${clusterName:-DMS}
keySize=${keySize:-2048}

pwd=''


if [[ $generatePwd == "y" ]]; then
   echo 'Generating secure password for keystores'
   pwd=$(openssl rand -hex 20)
   echo "Generated password is $pwd"
   #pwd="123456" #TODO generate one! Keytool min is 6 chars
else
   read -s -p 'Please enter a password for the certificates and truststores: ' pwd
   echo
   read -s -p 'Please re-enter the password: ' pwdConfirmation
   echo

   # Verify passwords match
   if [[ "$pwd" != "$pwdConfirmation" ]]; then
      echo -e "${RED}Invalid input:${NC} Passwords did not match"
      exit 3
   fi

   pwdLength=${#pwd}

   if [[ pwdLength -le 10 ]]; then
      echo -e "${RED}Invalid input:${NC} Minimum password length is 10 characters"
      exit 4
   fi
fi

# Verify validity is >= 30 days and <= 3650 days
re='^[0-9]+$'

if ! [[ $validity =~ $re  ]]; then
   echo -e "${RED}Invalid input:${NC} Certificate validity should be numeric (days)"
   exit 5
fi

if [[ $validity -le 29 || $validity -ge 3651 ]]; then
   echo -e "${RED}Invalid input:${NC} Certificate validity should be between 30 and 3650 days"
   exit 6
fi

#TODO: verify hostnames aren't empty


# Verify keySize is valid (1024, 2048, 4096, 8192)
if [[ $keySize != 1024 && $keySize != 2048 && $keySize != 4096 && $keySize != 8192 ]]; then
   echo -e "${RED}Invalid input:${NC} Key size should be of size 1024, 2048, 4096 or 8192 bit"
   exit 6
fi

# Log what we learned
echo '---- Generating Certificates ----'
echo Cluster name: $clusterName
echo Nodes: ${hostNames[@]}
echo Validity: $validity
echo Key size: $keySize
echo Resolve hostnames? $resolveHostName

# Cleanup previous runs
echo 'Removing files from previous executions'
find . -type f -iname \*.jks -delete
find . -type f -iname \*.conf -delete
find . -type f -iname \*.key -delete
find . -type f -iname \*.crt -delete
find . -type f -iname \*.crt_signed -delete
find . -type f -iname \*.crs -delete
find . -type f -iname \*.cer -delete
find . -type f -iname \*.crl -delete

echo 'Generating new Root CA certificate'

# Create config file to create Root CA cert from
echo "[req]
distinguished_name  = req_distinguished_name
prompt              = no
output_password     = $pwd
default_bits        = $keySize

[req_distinguished_name]
C     = BE
O     = Cassandra
CN    = rootCA
OU    = $clusterName" > generate_rootCA.conf

# Create a new Root CA certificate and store the private key in rootCA.key, public key in rootCA.crt
openssl req -config generate_rootCA.conf -new -x509 -nodes -keyout rootCA.key -out rootCA.crt -days $validity

# Create new JKS trustore and add Root CA certificate
echo "Creating Root CA truststore (JKS)"
keytool -keystore rootCA-truststore.jks -storetype JKS -importcert -file rootCA.crt -keypass $pwd -storepass $pwd -alias rootCA -noprompt

# Create a certificate for every node
for i in "${hostNames[@]}"
do
   echo
   echo "Generating certificate for node: $i"
   nodeIp=""

   if [[ $resolveHostName == "y" ]]; then
      # Resolve the hostname to the ip
      echo "Resolving $i to IP..."
      tempIp=$(dig $i +short)

      if [[ $tempIp =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
         echo "Resolved $i to IP: $tempIp"
         nodeIp=$tempIp
      else
         echo "Failed to resolve $i to a valid IP."
      fi
   fi

   if [[ $nodeIp == '' ]]; then
      read -p "Please enter the IP address for node $i: " nodeIp
   fi

   # Importing the public Root CA certificate in node keystore
   echo "Importing Root CA certificate in node keystore"
   keytool -keystore $i-node-keystore.jks -alias rootCA -importcert -file rootCA.crt -keypass $pwd -storepass $pwd -noprompt

   echo "Generating new key pair for node: $i"
   keytool -genkeypair -keyalg RSA -alias $i -keystore $i-node-keystore.jks -storepass $pwd -keypass $pwd -validity $validity -keysize $keySize -dname "CN=$i, OU=$clusterName, O=Cassandra, C=BE" -ext "san=ip:$nodeIp"

   echo "Creating signing request"
   keytool -keystore $i-node-keystore.jks -alias $i -certreq -file $i.csr -keypass $pwd -storepass $pwd

   # Add both hostname and IP as subject alternative name
   echo "subjectAltName=DNS:$i,IP:$nodeIp" > $i_san.conf

   # Sign the node certificate with the private key of the rootCA
   echo "Signing certificate with Root CA certificate"
   openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in $i.csr -out $i.crt_signed -days $validity -CAcreateserial -passin pass:$pwd -extfile $i_san.conf

   # Import the signed certificate in the node key store
   echo "Importing signed certificate for $i in node keystore"
   keytool -keystore $i-node-keystore.jks -alias $i -importcert -file $i.crt_signed -keypass $pwd -storepass $pwd -noprompt

   # Export the public key for every node
   echo "Exporting public key for $i"
   keytool -exportcert -alias $i -keystore $i-node-keystore.jks -file $i-public-key.cer -storepass $pwd

   # Log the certificates for this node (for debugging purposes)
   #echo "Certificates in node-keystore for $i:"
   #keytool -list -keystore $i-node-keystore.jks -storepass $pwd

   # Create keystore with public cert (mostly for CQL clients like DevCenter)
   echo "Creating public truststore for clients"
   keytool -keystore $i-public-truststore.jks -alias $i -importcert -file $i-public-key.cer -keypass $pwd -storepass $pwd -noprompt

   echo "Finished for $i"
   echo
done

# Add the public key of every node to the keystore of every other node (when there are multiple nodes)
nodeCount=${#hostNames}

if [[ nodeCount -ge 2 ]]; then
   for i in "${hostNames[@]}"
   do
      echo "Adding public key from $i to all other node keystores"
      for j in "${hostNames[@]}"
      do
         if [[ $i == $j  ]]; then
            continue # We already added it to our store
         fi

         echo "Importing cert from $j in $i node keystore"
         keytool -keystore $i-node-keystore.jks -alias $j -importcert -file $j-public-key.cer -keypass $pwd -storepass $pwd -noprompt
      done
      echo
      echo "Certificates in node keystore from $i"
      keytool -list -keystore $i-node-keystore.jks -storepass $pwd
      echo
   done
fi

echo "---- Finished updating certificates ----"
echo
echo

# TODO: possible the root CA is enough!
echo -e "Copy the following certificates ${YELLOW}to every Cassandra client${NC}:"
ls -d *rootCA.crt

echo
echo -e "Copy the following keystores to the ${YELLOW}matching Cassandra node${NC}:"
ls -d *-node-keystore.jks

echo
echo -e "Use the following trust stores to connect using ${YELLOW}DevCenter${NC}:"
ls -d *-public-truststore.jks

echo
echo -e "Keep the following files ${YELLOW}PRIVATE${NC}:"
ls -d rootCA*

echo
echo
echo "Deleting unused files..."
find . -type f -iname \*.crt_signed -delete
find . -type f -iname \*.csr -delete
find . -type f -iname \*.conf -delete

if [[ $generatePwd == "y" ]]; then
   echo -e "The certificate ${YELLOW}password${NC} is: $pwd"
fi

echo 'Script completed'
exit 0