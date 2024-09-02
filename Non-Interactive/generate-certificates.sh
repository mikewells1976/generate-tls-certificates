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
generatePwd="y"
useExisting="n"
rootCAcrtInput=""
rootCAkeyInput=""
rootCAPassword=""
sanFile=""
ipAddresses=()

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
    -s  Path to Subject Alternative Names file
    -h  Comma-separated list of IPs
  "
  exit 1
}

# Parse command-line arguments
while getopts "d:o:c:v:k:g:u:i:j:p:s:h:" opt; do
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
    s ) sanFile="$OPTARG" ;;
    h ) IFS=',' read -r -a ipAddresses <<< "$OPTARG" ;;
    * ) usage ;;
  esac
done

validate_sans_file() {
  if [[ -z "$sanFile" ]]; then
    echo -e "${RED}Error: SANs file must be provided using the -s option.${NC}"
    exit 1
  elif [[ ! -f "$sanFile" ]]; then
    echo -e "${RED}Error: SANs file '$sanFile' does not exist.${NC}"
    exit 1
  fi
}

validate_cluster_name() {
    if [[ $(grep -P "[\x80-\xFF]" <<< $cluster_name) ]]; then
        echo -e "${RED}Warning:${NC} Your cluster name contains non-ASCII characters. This may prevent your nodes from starting up if you have internode encryption turned on."
        exit 1
    fi
}

validate_organization() {
    if [[ "${organization,,}" != "cassandra" && "${organization,,}" != "elastic" && "${organization,,}" != "opensearch" && "${organization,,}" != "nats" ]]; then
      echo -e "${RED}Invalid input:${NC} instance type should be Cassandra, Elastic, OpenSearch or NATS"
      exit 1
    fi
}

validate_root_ca_inputs() {
  if [[ "$useExisting" == "y" ]]; then
    if [[ -z "$rootCAcrtInput" || -z "$rootCAkeyInput" ]]; then
      echo -e "${RED}Error: When using an existing Root CA, both -i and -j options are required.${NC}"
      usage
    fi
    if [[ -z "$rootCAPassword" ]]; then
      echo -e "${RED}Error: When using an existing Root CA, a Root CA password must be provided.${NC}"
      usage
    fi
  else
    if [[ -n "$rootCAcrtInput" || -n "$rootCAkeyInput" ]]; then
      echo -e "${YELLOW}Warning: Since 'useExisting' is set to 'n', the provided Root CA inputs will not be used.${NC}"
    fi
    rootCAcrtInput="rootCA.crt"
    rootCAkeyInput="rootCA.key"
  fi
}


validate_ip_addresses_provided() {
  if [[ ${#ipAddresses[@]} -eq 0 ]]; then
    echo -e "${RED}Error: At least one IP must be provided using the -h option.${NC}"
    usage
  fi
}

validate_certificate_validity() {
  re='^[0-9]+$'
  
  if ! [[ $validity =~ $re ]]; then
    echo -e "${RED}Invalid input:${NC} Certificate validity should be numeric (days)."
    exit 1
  elif [[ $validity -lt 30 || $validity -gt 3650 ]]; then
    echo -e "${RED}Invalid input:${NC} Certificate validity should be between 30 and 3650 days."
    exit 1
  fi
}

validate_key_size() {
  if [[ $keySize != 1024 && $keySize != 2048 && $keySize != 4096 && $keySize != 8192 ]]; then
    echo -e "${RED}Invalid input:${NC} Key size should be one of the following: 1024, 2048, 4096, 8192 bits."
    exit 1
  fi
}



# Check for superuser privileges
check_superuser() {
  if [[ $(id -u) != 0 ]]; then
    echo -e "${RED}Permission Denied: Please run this script with superuser privileges.${NC}"
    exit 1
  fi
}

Validate() {
  validate_sans_file
  validate_cluster_name
  validate_organization
  validate_root_ca_inputs
  validate_ip_addresses_provided
  validate_certificate_validity
  validate_key_size
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

parse_sans_file() {
  declare -A sanMap
  local current_ip=""
  
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim leading/trailing whitespace
    line="$(echo -e "${line}" | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    
    if [[ -z "$line" ]]; then
      continue  # Skip empty lines
    elif [[ $line =~ ^\[(.+)\]$ ]]; then
      current_ip="${BASH_REMATCH[1]}"
      sanMap["$current_ip"]=""  # Initialize SAN entry
    elif [[ -n "$current_ip" ]]; then
      if [[ -z "${sanMap[$current_ip]}" ]]; then
        sanMap["$current_ip"]="$line"
      else
        sanMap["$current_ip"]+=",${line}"
      fi
    else
      echo -e "${RED}Error: SAN entry found before any node IP is specified.${NC}"
      exit 1
    fi
  done < "$sanFile"

  # Return the associative array
  echo "$(declare -p sanMap)"
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

# Generate certificates for each IP address
generate_node_certificates() {
  eval "$(parse_sans_file)"

  for ip in "${ipAddresses[@]}"; do
    echo -e "\nGenerating certificate for IP: $ip"
    validate_ip $ip
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}Invalid IP address provided: $ip${NC}"
      exit 1
    fi

    san="${sanMap[$ip]}"

    import_root_ca $ip
    generate_keypair $ip "$san"
    create_signing_request $ip
    sign_certificate $ip "$san"
    import_signed_certificate $ip
    export_public_key $ip
    echo "Finished for $ip"
  done
}

# Import Root CA into node keystore
import_root_ca() {
  local ip="$1"
  keytool -keystore "${ip}-node-keystore.jks" -alias rootCA -importcert -file $rootCAcrtInput -keypass $rootCAPassword -storepass $rootCAPassword -noprompt
}

# Generate key pair for node
generate_keypair() {
  local ip="$1"
  local san="$2"
  keytool -genkeypair -keyalg RSA -alias $ip -keystore "${ip}-node-keystore.jks" \
    -storepass $rootCAPassword -keypass $rootCAPassword -validity $validity -keysize $keySize \
    -dname "CN=$ip, OU=$clusterName, O=$organization, C=BE" -ext san="$san"
}

# Create certificate signing request
create_signing_request() {
  local ip="$1"
  keytool -keystore "${ip}-node-keystore.jks" -alias $ip -certreq -file "${ip}.csr" \
    -keypass $rootCAPassword -storepass $rootCAPassword
}

# Sign node certificate with Root CA
sign_certificate() {
  local ip="$1"
  echo "subjectAltName=$san" > "${ip}.conf"
  openssl x509 -req -CA $rootCAcrtInput -CAkey $rootCAkeyInput -in "${ip}.csr" -out "${ip}.crt_signed" -days $validity -CAcreateserial -passin pass:$rootCAPassword -extfile "${ip}.conf"
}

# Import signed certificate into keystore
import_signed_certificate() {
  local ip="$1"
  keytool -keystore "${ip}-node-keystore.jks" -alias $ip -importcert -file "${ip}.crt_signed" -keypass $rootCAPassword -storepass $rootCAPassword -noprompt
}

# Export public key
export_public_key() {
  local ip="$1"
  keytool -exportcert -alias $ip -keystore "${ip}-node-keystore.jks" -file "${ip}-public-key.cer" -storepass $rootCAPassword
  keytool -importkeystore -srckeystore "${ip}-node-keystore.jks" -destkeystore "${ip}-node-keystore.p12" -srcstoretype JKS -deststoretype PKCS12 -srcstorepass $rootCAPassword -deststorepass $rootCAPassword
}

# Generate Admin certificate
generate_admin_certificate() {
  echo "Generating the Admin certificate"

  echo "[ req ]
  distinguished_name  = req_distinguished_name
  prompt              = no
  output_password     = \"$rootCAPassword\"
  default_bits        = $keySize

  [ req_distinguished_name ]
  C     = BE
  O     = $organization
  CN    = Admin
  OU    = \"$clusterName\"" > Admin.conf


  # generate new keypair
  openssl genrsa -out admin_key.tmp $keySize

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
  Validate
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
