# TLS Encryption Configuration Script
These scripts streamline the creation of TLS certificates to ensure the security of **Cassandra**, **ElasticSearch**, **OpenSearch**, or **NATS** instances. They automate the entire process, encompassing the generation of a Root Certificate Authority (CA) certificate, node-specific certificates, and seamless certificate management tasks.

## Prerequisites
- Ensure you have Administrator privileges to execute the scripts successfully.
- Ensure that **openssl.exe** and **keytool.exe** are available on your system. 

### Linux/Mac
#### Openssl
1. Open a terminal.
2. Check the available OpenJDK versions
   ```bash
    apt search openjdk
    ```
4. Install the desired OpenJDK version
    ```bash
    sudo apt-get update
    sudo apt-get install openjdk-[VERSION]-jdk
     ```
    
#### Keytool
1. If you already have OpenJDK installed and just need to ensure Keytool is available by running

    ```bash
    which keytool
     ```
     
### Windows
#### OpenSSL
1. Check if OpenSSL is installed and retrieve its location by executing the command:
    ```powershell
    Get-Command openssl
    ```
   If it is not installed, consider installing it alongside with [Git](https://git-scm.com/downloads).

    
#### Keytool
1. Check if Keytool is installed and retrieve its location by executing the command:
    ```powershell
    Get-Command keytool
    ```
   If it is not installed, consider installing it alongside with [OpenJDK](https://openjdk.org/).
   
## Usage 
### Running `generate-certificates.sh` (Linux/Mac)

1. Open a terminal.
2. Navigate to the directory containing `generate-tls-certificates.sh`.
3. Run the following command:

    ```bash
    chmod +x generate-certificates.sh
    ```

    This step ensures execution permissions.

4. Execute the script:

    ```bash
    ./generate-certificates.sh
    ```

### Running `generate-certificates.ps1` (Windows)

1. Open PowerShell.
2. Navigate to the directory containing `generate-tls-certificates.ps1`.
3. Execute the script:

    ```powershell
    .\generate-certificates.ps1
    ```
    
> [!NOTE]
> Ensure the necessary executables and prerequisites are in place before running the scripts.


## Features
- **Organization Type:** Choose the instance type for which you want to generate certificates (Cassandra, Elastic, OpenSearch, NATS).
- **Cleanup:** Option to clean up files generated in previous executions.
- **Cluster Information:** Enter the name of your cluster and handle non-ASCII characters appropriately.
- **Certificate Options:** Set the validity period for the certificates.
- **Key Size:** Choose the certificate key size (1024, 2048, 4096, or 8192 bits).
- **Hostnames:** Input the hostnames (FQDN) of each node.
- **Automatic Hostname Resolution:** Option to resolve hostnames automatically instead of manually entering IP addresses.
- **Root CA Certificate:** Choose to use an existing root certificate or generate a new one.
- **Certificate Generation:** Automatically generates certificates for each node in the cluster.
- **Subject Alternative Names (SANs):** Specify additional SANs for each node.
- **Password Handling:** Option to automatically generate a secure password or manually enter one.
- **Public Key Exchange:** Add public keys of every node to the keystore of every other node.
- **Cleanup Unused Files:** Remove unnecessary files generated during the execution.
- **Certificates Information:** Display information about the generated certificates, keystore files, and passwords.

> [!IMPORTANT]
> - Ensure the root CA certificate (rootCA.crt) is trusted on every client. **If a password is generated, note it down for future reference.**
> - Copy the generated keystore files (*-node-keystore.p12) to their respective nodes.

## License:
This script is provided under the [MIT License](https://github.com/SkylineCommunications/generate-tls-certificates/blob/main/LICENSE.md).
