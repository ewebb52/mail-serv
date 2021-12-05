#/bin/bash
HOME=$(pwd)

# if [ -d "$HOME/ca" ]
# then 
# 	echo "CA exists"
# 	exit 1
# fi

echo ""
echo "Starting OpenSSL"

echo " "
echo "Preparing the directory"

mkdir ca
cd ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt index.txt.attr
echo 1000 > serial

echo """# OpenSSL CA configuration file.

[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME
certs             = $HOME/ca/certs
crl_dir           = $HOME/ca/crl
new_certs_dir     = $HOME/ca/newcerts
database          = $HOME/ca/index.txt
serial            = $HOME/ca/serial
RANDFILE          = $HOME/ca/private/.rand

# The root key and root certificate.
private_key       = $HOME/ca/private/ca.key.pem
certificate       = $HOME/ca/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/ca/crlnumber
crl               = $HOME/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = NY
localityName_default            = .
0.organizationName_default      = Valgrind Ltd
organizationalUnitName_default  = .
commonName_default		= Valgrind Ltd
emailAddress_default            = .


[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning""" > openssl.cnf

echo ""
echo "openssl.cnf file ca directory complete"
echo ""

echo ""
echo "creating root key"
echo ""

openssl genrsa -aes256 -out private/ca.key.pem 4096

chmod 400 private/ca.key.pem

echo ""
echo "root key completed.  Creating root certificate"
echo ""

openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem

chmod 444 certs/ca.cert.pem

echo ""
echo "Root certificate complete.  Verifying root"
echo ""

openssl x509 -noout -text -in certs/ca.cert.pem

echo ""
echo "Creating intermediate directory"
echo ""


mkdir intermediate
cd intermediate
mkdir certs crl csr newcerts private temp
chmod 700 private
touch index.txt index.txt.attr
echo 1000 > serial
echo 1000 > crlnumber

echo ""
echo "intermediate directory configured.  Creating openssl.cnf for intermediate"
echo ""

echo """# OpenSSL intermediate CA config file
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/ca/intermediate
certs             = $HOME/ca/intermediate/certs
crl_dir           = $HOME/ca/intermediate/crl
new_certs_dir     = $HOME/ca/intermediate/newcerts
database          = $HOME/ca/intermediate/index.txt
serial            = $HOME/ca/intermediate/serial
RANDFILE          = $HOME/ca/intermediate/private/.rand

# The root key and root certificate.
private_key       = $HOME/ca/intermediate/private/intermediate.key.pem
certificate       = $HOME/ca/intermediate/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/ca/intermediate/crlnumber
crl               = $HOME/ca/intermediate/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = NY
localityName_default            =
0.organizationName_default      = Valgrind Ltd
organizationalUnitName_default  =
commonName_default		= Valgrind Intermediate CA Ltd
emailAddress_default            =

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning""" > openssl.cnf

echo ""
echo "openss.cnf for intermediate done.  creating intermediate key"
echo ""

cd ..
# in /ca
openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096
chmod 400 intermediate/private/intermediate.key.pem


echo ""
echo "Key generated.  Creating intermediate certificate"
echo ""

openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem

openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem


chmod 444 intermediate/certs/intermediate.cert.pem

echo ""
echo "Intermediate Cert created.  Now veryifying cert"
echo ""

openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

echo ""
echo "Intermediate Cert verified.  Creating certificate chain file"
echo ""

cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem

echo ""
echo "Certificate chain file created. Creating Server Key"
echo ""
# ######################################################################################################
# #FIX HERE
# openssl rsa -aes256 -out intermediate/private/server.key.pem 2048
# chmod 400 intermediate/private/www.example.com.key.pem
# ######################################################################################################


#ORIGINAL
#############################################################################
openssl genrsa -aes256 -out intermediate/private/www.example.com.key.pem 2048
chmod 400 intermediate/private/www.example.com.key.pem
#############################################################################

echo ""
echo "Creating Server config file."
echo ""

cd intermediate

#Server config file
#TODO Update?
echo """# OpenSSL intermediate CA Server config file.

[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/ca/intermediate
certs             = $HOME/ca/intermediate/certs
crl_dir           = $HOME/ca/intermediate/crl
new_certs_dir     = $HOME/ca/intermediate/newcerts
database          = $HOME/ca/intermediate/index.txt
serial            = $HOME/ca/intermediate/serial
RANDFILE          = $HOME/ca/intermediate/private/.rand

# The root key and root certificate.
private_key       = $HOME/ca/intermediate/private/intermediate.key.pem
certificate       = $HOME/ca/intermediate/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/ca/intermediate/crlnumber
crl               = $HOME/ca/intermediate/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

countryName_default             = US
stateOrProvinceName_default     = NY
localityName_default            =
0.organizationName_default      = Valgrind Ltd
organizationalUnitName_default  =
commonName_default		= 127.0.0.1
emailAddress_default            =

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning""" > opensslserver.cnf

## Cient config file
#TODO fix email
echo """# OpenSSL intermediate CA client configuration file.

[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/ca/intermediate
certs             = $HOME/ca/intermediate/certs
crl_dir           = $HOME/ca/intermediate/crl
new_certs_dir     = $HOME/ca/intermediate/newcerts
database          = $HOME/ca/intermediate/index.txt
serial            = $HOME/ca/intermediate/serial
RANDFILE          = $HOME/ca/intermediate/private/.rand

# The root key and root certificate.
private_key       = $HOME/ca/intermediate/private/intermediate.key.pem
certificate       = $HOME/ca/intermediate/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/ca/intermediate/crlnumber
crl               = $HOME/ca/intermediate/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = NY
localityName_default            =
0.organizationName_default      = Valgrind Ltd
organizationalUnitName_default  =
commonName_default		= Valgrind Ltd
emailAddress_default            = valgrind@columbia.edu

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning""" > opensslclient.cnf

cd ..
#in /ca/

echo ""
echo "Creating server certificate"
echo ""

openssl rsa -in intermediate/private/www.example.com.key.pem -out intermediate/private/server.key.pem

openssl req -config intermediate/opensslserver.cnf -key intermediate/private/server.key.pem -new -sha256 -out intermediate/csr/server.csr.pem

openssl ca -config intermediate/opensslserver.cnf -extensions server_cert -days 375 -notext -md sha256 -in intermediate/csr/server.csr.pem -out intermediate/certs/server.cert.pem

chmod 444 intermediate/certs/server.cert.pem

echo ""
echo "Verify the Server Certificate"
echo ""

openssl x509 -noout -text -in intermediate/certs/server.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/server.cert.pem

rm intermediate/private/www.example.com.key.pem

# ORIGINAL
# openssl req -config intermediate/opensslserver.cnf -key intermediate/private/www.example.com.key.pem -new -sha256 -out intermediate/csr/www.example.com.csr.pem

# openssl ca -config intermediate/opensslserver.cnf -extensions server_cert -days 375 -notext -md sha256 -in intermediate/csr/www.example.com.csr.pem -out intermediate/certs/www.example.com.cert.pem

# chmod 444 intermediate/certs/www.example.com.cert.pem

# echo ""
# echo "Verify the Server Certificate"
# echo ""

# openssl x509 -noout -text -in intermediate/certs/www.example.com.cert.pem
# openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/www.example.com.cert.pem
# END ORIGINAL


echo ""
echo "end of generating root/intermediate certs."

cd ..
sudo chown -R $SUDO_USER ca
chmod 700 $(find $HOME/ca/ -type d)
chmod 600 $(find $HOME/ca/ -type f)

exit 1