#!/bin/bash

# Constants for colored output
YELLOW="\033[1;33m"
RED="\033[31m"
NC="\033[0m"

# Default values
delete_files="y"
organization="Cassandra"
clusterName="DMS"
validity=365
keySize=4096
resolveHostName="y"
generatePwd="y"
useExisting="n"
rootCAcrtInput=""
rootCAkeyInput=""
rootCAPassword=""
hostNames=()

# Display usage instructions
usage() {
  echo -e "Usage: $0 [options]
  Options:
    -d  Delete previous files (y/n) [default: y]
    -o  Organization name [default: Cassandra]
    -c  Cluster name [default: DMS]
    -v  Certificate validity in days [default: 365]
    -k  Key size [default: 4096]
    -g  Generate secure password (y/n) [default: y]
    -u  Use existing Root CA (y/n) [default: n]
    -i  Path to existing Root CA certificate
    -j  Path to existing Root CA key
    -p  Root CA password
    -h  Comma-separated list of IPs
  "
  exit 1
}

# Parse command-line arguments
while getopts "d:o:c:v:k:r:g:u:i:j:p:h:" opt; do
  case ${opt} in
    d ) delete_files="$OPTARG" ;;
    o ) organization="$OPTARG" ;;
    c ) clusterName="$OPTARG" ;;
    v ) validity="$OPTARG" ;;
    k ) keySize="$OPTARG" ;;
    g ) generatePwd="$OPTARG" ;;
    u ) useExisting="$OPTARG" ;;
    i ) rootCAcrtInput="$OPTARG" ;;
    j ) rootCAkeyInput="$OPTARG" ;;
    p ) rootCAPassword="$OPTARG" ;;
    h ) IFS=',' read -r -a hostNames <<< "$OPTARG" ;;
    * ) usage ;;
  esac
done

# Validate required parameters
if [[ "$useExisting" == "y" && ( -z "$rootCAcrtInput" || -z "$rootCAkeyInput" ) ]]; then
  echo -e "${RED}Error: When using an existing Root CA, both -i and -j options are required.${NC}"
  usage
else
  rootCAcrtInput="rootCA.crt"
  rootCAkeyInput="rootCA.key"
fi

if [[ ${#hostNames[@]} -eq 0 ]]; then
  echo -e "${RED}Error: At least one IP must be provided using the -h option.${NC}"
  usage
fi

# Check for superuser privileges
check_superuser() {
  if [[ $(id -u) != 0 ]]; then
    echo -e "${RED}Permission Denied: Please run this script with superuser privileges.${NC}"
    exit 1
  fi
}

# Clean up files from previous runs
cleanup_files() {
  if [[ $delete_files == "y" ]]; then
    echo -e "${YELLOW}Removing files from previous executions...${NC}"
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

# Modify PATH for OpenSearch
set_opensearch_path() {
  if [[ "${organization,,}" == "opensearch" ]]; then
    PATH+=:/usr/share/opensearch/jdk/bin/
    echo "Using OpenSearch: PATH modified to include java keytool."
  fi
}

# Generate secure password if needed
generate_password() {
  if [[ $generatePwd == "y" ]]; then
    pwd=$(openssl rand -hex 20)
    rootCAPassword=$pwd
  fi
}

# Validate IP address
validate_ip() {
  local ip="$1"
  local pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

  if [[ $ip =~ $pattern ]]; then
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
      if ! [[ $octet =~ ^[0-9]+$ ]] || ((10#$octet < 0 || 10#$octet > 255)); then
        return 1
      fi
    done
    return 0
  else
    return 1
  fi
}

# Generate Root CA certificate
generate_root_certificate() {
  if [[ $useExisting == "y" ]]; then
    echo "Using existing Root CA certificate at $rootCAcrtInput"
  else
    echo "Generating new Root CA certificate..."
    cat > generate_rootCA.conf <<EOF
[req]
distinguished_name  = req_distinguished_name
prompt              = no
output_password     = "$rootCAPassword"
default_bits        = $keySize

[req_distinguished_name]
C     = BE
O     = $organization
CN    = rootCA
OU    = "$clusterName"
EOF

    openssl req -config generate_rootCA.conf -new -x509 -nodes -keyout $rootCAkeyInput -out rootCA.crt -days $validity
    keytool -keystore rootCA-truststore.jks -storetype JKS -importcert -file $rootCAcrtInput -keypass $rootCAPassword -storepass $rootCAPassword -alias rootCA -noprompt
  fi
}

# Generate certificates for each node
generate_node_certificates() {
  for host in "${hostNames[@]}"; do
    echo -e "\nGenerating certificate for node: $host"
    validate_ip $host
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}Invalid IP address provided: $host${NC}"
      exit 1
    fi
    import_root_ca $host
    generate_keypair $host
    create_signing_request $host
    sign_certificate $host
    import_signed_certificate $host
    export_public_key $host
    echo "Finished for $host"
  done
}

# Import Root CA into node keystore
import_root_ca() {
  local host="$1"
  keytool -keystore "${host}-node-keystore.jks" -alias rootCA -importcert -file $rootCAcrtInput -keypass $rootCAPassword -storepass $rootCAPassword -noprompt
}

# Generate key pair for node
generate_keypair() {
  local host="$1"
  keytool -genkeypair -keyalg RSA -alias $host -keystore "${host}-node-keystore.jks" \
    -storepass $rootCAPassword -keypass $rootCAPassword -validity $validity -keysize $keySize \
    -dname "CN=$host, OU=$clusterName, O=$organization, C=BE" -ext san="ip:$host"
}

# Create certificate signing request
create_signing_request() {
  local host="$1"
  keytool -keystore "${host}-node-keystore.jks" -alias $host -certreq -file "${host}.csr" \
    -keypass $rootCAPassword -storepass $rootCAPassword
}

# Sign node certificate with Root CA
sign_certificate() {
  local host="$1"
  echo "subjectAltName=IP:$host" > "${host}.conf"
  openssl x509 -req -CA $rootCAcrtInput -CAkey $rootCAkeyInput -in "${host}.csr" -out "${host}.crt_signed" -days $validity -CAcreateserial -passin pass:$rootCAPassword -extfile "${host}.conf"
}

# Import signed certificate into keystore
import_signed_certificate() {
  local host="$1"
  keytool -keystore "${host}-node-keystore.jks" -alias $host -importcert -file "${host}.crt_signed" -keypass $rootCAPassword -storepass $rootCAPassword -noprompt
}

# Export public key
export_public_key() {
  local host="$1"
  keytool -exportcert -alias $host -keystore "${host}-node-keystore.jks" -file "${host}-public-key.cer" -storepass $rootCAPassword
  keytool -importkeystore -srckeystore "${host}-node-keystore.jks" -destkeystore "${host}-node-keystore.p12" -srcstoretype JKS -deststoretype PKCS12 -srcstorepass $rootCAPassword -deststorepass $rootCAPassword
}

# Generate Admin certificate
generate_admin_certificate() {
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
	openssl x509 -req -CA $rootCAcrtInput -CAkey $rootCAkeyInput -in admin.csr -out admin.pem -days $validity -CAcreateserial -passin pass:$rootCAPassword
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

  echo -e "${YELLOW}Please make sure the $rootCAcrtInput is trusted on every client"

  echo -e "${YELLOW}Copy the following keystores to the matching node:${NC}"
  ls -d *-node-keystore.p12

  if [[ $generatePwd == "y" ]]; then
    echo -e "${YELLOW}Generated password is: $pwd${NC}"
  fi

  echo 'Script completed'
  exit 0
}

main() {
  check_superuser
  cleanup_files
  set_opensearch_path
  generate_password
  generate_root_certificate
  generate_node_certificates
  if [[ "${organization,,}" == "opensearch" ]]; then
    generate_admin_certificate
  fi
  cleanup_unused_files
  display_certificates_info
}

main
