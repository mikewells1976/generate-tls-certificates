#!/bin/bash
# Run this script like: bash <filename>.sh

YELLOW="\033[1;33m"
RED="\033[31m"
NC="\033[0m"

# Verify superuser privileges
check_superuser() {
  if [[ $(id -u) != 0 ]]; then
    echo 'Permission Denied: Please run this script with superuser privileges.'
    exit 1
  fi
}

# Cleanup previous runs
cleanup_files() {
  read -p 'Do you want to clean up the files generated during a previous execution? [Default: y, Options y|n] ' delete
  delete=${delete:-y}
  if [[ $delete == "y" ]]; then
    echo 'Removing files from previous executions'
    find . -type f -iname \*.jks -delete
    find . -type f -iname \*.conf -delete
    find . -type f -iname \*.key -delete
    find . -type f -iname \*.crt -delete
    find . -type f -iname \*.crt_signed -delete
    find . -type f -iname \*.crs -delete
    find . -type f -iname \*.cer -delete
    find . -type f -iname \*.crl -delete
    find . -type f -iname \*.p12 -delete
    find . -type f -iname \*.pem -delete
  fi
}

# Asking for organization type and verify
get_organization_type() {
  while true; do
    read -p 'Which instance are you generating certificates for? [Default: Cassandra, Options: Cassandra|Elastic|OpenSearch|NATS] ' organization
    organization=${organization:-Cassandra}
    if [[ "${organization,,}" != "cassandra" && "${organization,,}" != "elastic" && "${organization,,}" != "opensearch" && "${organization,,}" != "nats" ]]; then
      echo -e "${RED}Invalid input:${NC} instance type should be Cassandra, Elastic, OpenSearch or NATS"
    else
      break
    fi
  done
}

# Setting the PATH variable for OpenSearch
set_opensearch_path() {
  if [[ "${organization,,}" == "opensearch" ]]; then
    PATH+=:/usr/share/opensearch/jdk/bin/
    echo "When choosing OpenSearch, PATH is temporarily modified to include java keytool"
    echo "Contents of the PATH variable: $PATH"
  fi
}

# Asking for cluster information and verify
get_cluster_info() {
  while true; do
    read -p 'Please enter the name of your cluster: [Default: DMS] ' clusterName
    clusterName=${clusterName:-DMS}
    if [[ $(grep -P "[\x80-\xFF]" <<< $clusterName) ]]; then
      echo -e "${RED}Warning:${NC} Your clustername contains non-ASCII characters. This may prevent your nodes from starting up if you have internode encryption turned on."
      read -p "Do you want to proceed? (May cause your cluster to fail to start) [Default: n, Options y|n] " proceed
      proceed=${proceed:n}
      if [[ $proceed != "y" ]]; then
        echo "Quitting..."
      fi
    else 
      break
    fi
  done
}

# Asking for certificate validity and verify
get_certificate_options() {
  while true; do
    read -p 'How long (days) should the certificates remain valid? [Default: 365 days, Min: 30, Max: 3650]? ' validity
    validity=${validity:-365}
    re='^[0-9]+$'
  
    if ! [[ $validity =~ $re ]]; then
      echo -e "${RED}Invalid input:${NC} Certificate validity should be numeric (days)"
    elif [[ $validity -le 29 || $validity -ge 3651 ]]; then
      echo -e "${RED}Invalid input:${NC} Certificate validity should be between 30 and 3650 days"
    else
      break
    fi
  done
}

# Asking for key size and verify
get_key_size() {
  while true; do
    read -p 'How long (bit) should the certificate key size be? [Default: 4096 bit, Options: 1024|2048|4096|8192]? ' keySize
    keySize=${keySize:-4096}
    if [[ $keySize != 1024 && $keySize != 2048 && $keySize != 4096 && $keySize != 8192 ]]; then
      echo -e "${RED}Invalid input:${NC} Key size should be of size 1024, 2048, 4096, or 8192 bit"
    else
      break
    fi
  done
}

# Getting hostnames of cluster
get_hostnames() {
  while true; do
    echo 'Please enter the hostnames (FQDN) of every node (space separated): '
    read -a hostNames

    if [[ "${#hostNames[@]}" -eq 0 ]]; then
      echo -e "${RED}Invalid input:${NC} No hostnames were provided, please provide at least one hostname"
    else
      break
    fi
  done
  read -p 'Do you want me to try to resolve the hostnames automatically instead of manually entering the IP addresses for every node? [Default: y, Options: y|n] ' resolveHostName
  resolveHostName=${resolveHostName:-y}
}

# Generate secure password for keystores
generate_password() {
  read -p "Do you want me to automatically generate a secure certificate password (instead of manually entering one)? [Default: y, Options: y|n] " generatePwd
  generatePwd=${generatePwd:-y}
  pwd=''
  if [[ $generatePwd == "y" ]]; then
    echo 'Generating secure password for keystores'
    pwd=$(openssl rand -hex 20)
  else
    read -s -p 'Please enter a password for the certificates and truststores: ' pwd
    echo
    read -s -p 'Please re-enter the password: ' pwdConfirmation
    echo

    if [[ "$pwd" != "$pwdConfirmation" ]]; then
      echo -e "${RED}Invalid input:${NC} Passwords did not match"
      exit 8
    fi

    pwdLength=${#pwd}

    if [[ pwdLength -le 10 ]]; then
      echo -e "${RED}Invalid input:${NC} Minimum password length is 10 characters"
      exit 9
    fi
  fi
}

validate_ip() {
    local ip="$1"
    local pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    if [[ $ip =~ $pattern ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            # Convert octet to integer for numerical comparison
            if ! [[ $octet =~ ^[0-9]+$ ]] || ((10#$octet < 0 || 10#$octet > 255)); then
                return 1  # Invalid IP address
            fi
        done
        return 0  # Valid IP address
    else
        return 1  # Invalid IP address
    fi
}

# Generate Root CA certificate
generate_root_certificate() {
  rootCAcrt="rootCA.crt"
  rootCAkey="rootCA.key"
  
  read -p 'Do you want to use an existing root certificate? [Default: y, Options y|n] ' useExisting
  useExisting=${useExisting:-y}
  if [[ $useExisting == "y" ]]; then
    # Ask for rootCA.crt file
    while true; do
      read -p 'Please enter the absolute path to the rootCA.crt file:' rootCAcrtInput
      if [ -e "$rootCAcrtInput" ] && [[ $rootCAcrtInput == *".crt"* ]]; then
        rootCAcrt=$rootCAcrtInput
        break  # Exit the loop if the condition is met
      else
        echo 'Invalid path. Please insert a valid path'
      fi
    done
    
    # Ask for rootCA.key file
    while true; do
      read -p 'Please enter the absolute path to the rootCA.key file:' rootCAkeyInput
      if [ -e "$rootCAkeyInput" ] && [[ $rootCAkeyInput == *".key"* ]]; then
        rootCAkey=$rootCAkeyInput
        break  # Exit the loop if the condition is met
      else
        echo 'Invalid path. Please insert a valid path'
      fi
    done

      # Ask for rootCA.key password
    while true; do
      read -p 'Please enter the password to the rootCA.key file:' rootCAPwdInput
      if [[ ! -z $rootCAPwdInput ]]; then
        rootCAPassword=$rootCAPwdInput
        break  # Exit the loop if the condition is met
      else
        echo 'Invalid password. Please insert a valid password'
      fi
    done
  else
    echo 'Generating new Root CA certificate'
    echo "[req]
    distinguished_name  = req_distinguished_name
    prompt              = no
    output_password     = \"$rootCAPassword\"
    default_bits        = $keySize

    [req_distinguished_name]
    C     = BE
    O     = $organization
    CN    = rootCA
    OU    = \"$clusterName\"" > generate_rootCA.conf

    openssl req -config generate_rootCA.conf -new -x509 -nodes -keyout $rootCAkey -out rootCA.crt -days $validity
    generate_password
    rootCAPassword=$pwd
    echo "Creating Root CA truststore (JKS)"
    keytool -keystore rootCA-truststore.jks -storetype JKS -importcert -file $rootCAcrt -keypass $rootCAPassword -storepass $rootCAPassword -alias rootCA -noprompt
  fi
}

# Generate certificates for every node
generate_node_certificates() {
  for i in "${hostNames[@]}"
    do
      echo
      echo "Generating certificate for node: $i"
      
      if [[ $resolveHostName == "y" ]]; then
        resolve_and_get_ip
      else
        get_valid_ip
      fi

      get_sans

      echo "Importing Root CA certificate in node keystore"
      keytool -keystore $i-node-keystore.jks -alias rootCA -importcert -file $rootCAcrt -keypass $rootCAPassword -storepass $rootCAPassword -noprompt

      echo "Generating new key pair for node: $i"
      keytool -genkeypair -keyalg RSA -alias $i -keystore $i-node-keystore.jks -storepass $rootCAPassword -keypass $rootCAPassword -validity $validity -keysize $keySize -dname "CN=$i, OU=$clusterName, O=$organization, C=BE" -ext $sans

      echo "Creating signing request"
      keytool -keystore $i-node-keystore.jks -alias $i -certreq -file $i.csr -keypass $rootCAPassword -storepass $rootCAPassword

      echo $subjectAltNames > "${i}.conf"

      echo "Signing certificate with Root CA certificate"
      openssl x509 -req -CA $rootCAcrt -CAkey $rootCAkey -in $i.csr -out $i.crt_signed -days $validity -CAcreateserial -passin pass:$rootCAPassword -extfile "${i}.conf"

      echo "Importing signed certificate for $i in node keystore"
      keytool -keystore $i-node-keystore.jks -alias $i -importcert -file $i.crt_signed -keypass $rootCAPassword -storepass $rootCAPassword -noprompt

      echo "Exporting public key for $i"
      keytool -exportcert -alias $i -keystore $i-node-keystore.jks -file $i-public-key.cer -storepass $rootCAPassword

      keytool -importkeystore -srckeystore $i-node-keystore.jks -destkeystore $i-node-keystore.p12 -srcstoretype JKS -deststoretype PKCS12 -srcstorepass $rootCAPassword -deststorepass $rootCAPassword

      if [[ "${organization,,}" == "nats" ]]; then
        echo "Generating PEM files"
        openssl pkcs12 -in "$i-node-keystore.p12" -out "$i-certificate.pem" -clcerts -nokeys -passin 'pass:'"$rootCAPassword"
        openssl pkcs12 -in "$i-node-keystore.p12" -out "$i-key.pem" -nocerts -nodes -passin 'pass:'"$rootCAPassword"

        # Remove the "Bag Attributes" section
        awk '/-----BEGIN CERTIFICATE-----/{flag=1; print $0; next} flag' "$i-certificate.pem" > temp_file && mv temp_file "$i-certificate.pem"
        awk '/-----BEGIN PRIVATE KEY-----/{flag=1; print $0; next} flag' "$i-key.pem" > temp_file && mv temp_file "$i-key.pem"

        # Remove .p12 file
        find . -type f -iname \*.p12 -delete
      fi

      echo "Finished for $i"
      echo
    done
}

# Generate an Admin certificate (only required for OpenSearch)
generate_admin_certificate(){
  echo "Generating the Admin certificate"

	echo "[ req ]
	distinguished_name  = req_distinguished_name
	prompt              = no
	output_password     = \"$rootCAPassword\"
	default_bits        = $keysize

	[ req_distinguished_name ]
	C     = BE
	O     = $organization
	CN    = Admin
	OU    = \"$clusterName\"" > Admin.conf


	# generate new keypair
	openssl genrsa -out admin_key.tmp $keysize

	# convert to PKCS8 format
	openssl pkcs8 -inform PEM -in admin_key.tmp -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem

	# generate signing request
	openssl req -new -key admin-key.pem -out admin.csr -config Admin.conf

	# sign the cert with the RootCA
	openssl x509 -req -CA $rootCAcrt -CAkey $rootCAkey -in admin.csr -out admin.pem -days $validity -CAcreateserial -passin pass:$rootCAPassword
}

# Gets additional Subject Alternative Names
get_sans(){
    read -p "Please specify additional SANs (Subject Alternative Names) (space separated) [Default: None]: " inputSans
    IFS=' ' read -ra sansArr <<< "$inputSans"

    sans="san=ip:$nodeIp"
    subjectAltNames="subjectAltName=IP:$nodeIp"

    for san in "${sansArr[@]}"; 
      do
          if validate_ip "$san"; then
            sans+=",ip:$san"
            subjectAltNames+=",IP:$san"
          else
            sans+=",dns:$san"
            subjectAltNames+=",DNS:$san"
          fi
      done
}

# Gets a valid IP Address
get_valid_ip() {
    while true; do
        read -p "Please enter the IP address for node $i: " ip_to_validate

        if validate_ip "$ip_to_validate"; then
            nodeIp=$ip_to_validate
            break
        else
            echo "Invalid IP. Please try again."
        fi
    done
}

# Resolves and gets the IP Address for the node
resolve_and_get_ip() {
    nodeIp=""

    echo "Resolving $i to IP..."
    tempIp=$(dig $i +short)

    if [[ $tempIp =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $tempIp != "127.0.0.1" ]]; then
        echo "Resolved $i to IP: $tempIp"
        nodeIp=$tempIp
    else
        echo "Failed to resolve $i to a valid IP."
        get_valid_ip
    fi
}

# Add public key of every node to the keystore of every other node
add_public_keys_to_keystore() {
  nodeCount=${#hostNames[@]}

  if [[ nodeCount -ge 2 ]]; then
    for i in "${hostNames[@]}"
    do
      echo "Adding public key from $i to all other node keystores"
      for j in "${hostNames[@]}"
      do
        if [[ $i == $j  ]]; then
          continue
        fi

        echo "Importing cert from $j in $i node keystore"
        keytool -keystore $i-node-keystore.p12 -alias $j -importcert -file $j-public-key.cer -keypass $rootCAPassword -storepass $rootCAPassword -noprompt
      done
    done
  fi
}

# Cleanup unused files
cleanup_unused_files() {
  find . -type f -iname \*.crt_signed -delete
  find . -type f -iname \*.csr -delete
  find . -type f -iname \*.conf -delete
  find . -type f -iname \*.srl -delete
  find . -type f -iname \*.tmp -delete
  find . -type f -iname \*.jks -delete
}

# Display certificates information
display_certificates_info() {
  echo "---- Finished updating certificates ----"

  echo -e "${YELLOW}Please make sure the $rootCAcrt is trusted on every client"

  echo -e "${YELLOW}Copy the following keystores to the matching node:${NC}"
  ls -d *-node-keystore.p12

  if [[ $generatePwd == "y" ]]; then
    echo -e "${YELLOW}Generated password is: $pwd${NC}"
  fi

  echo 'Script completed'
  exit 0
}

# Main execution
main() {
  check_superuser
  cleanup_files
  echo 'Starting Cassandra/Elastic/OpenSearch/NATS TLS encryption configuration...'
  get_organization_type
  set_opensearch_path
  get_cluster_info
  get_certificate_options
  get_key_size
  get_hostnames
  generate_root_certificate
  generate_node_certificates
  add_public_keys_to_keystore

  if [[ "${organization,,}" == "opensearch" ]]; then
    generate_admin_certificate
  fi

  cleanup_unused_files
  display_certificates_info
}

# Execute the main function
main