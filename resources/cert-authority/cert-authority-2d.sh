#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: ./cert-authority-2d.sh <private-key-filename>"
    exit
fi
echo $#

BASE="$PWD"
ROOT="${PWD}/root-2d/ca"
INIT="${PWD}/init"

if [ ! -d "root-2d" ]; then

### Create the root pair

# Prepare the directory
mkdir root-2d
cd root-2d
mkdir ca

cd $ROOT
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# Prepare the config file
cp "${BASE}/init/2d-openssl.cnf" "${ROOT}/openssl.cnf"

# Create the root key
cd $ROOT
openssl genrsa -aes256 -out private/ca.key.pem 4096 

# Create the root certificate
cd $ROOT
openssl req -config "${ROOT}/openssl.cnf" -key "${ROOT}/private/ca.key.pem" -new -x509 -out certs/ca.cert.pem

chmod 444 certs/ca.cert.pem

# Verify the root certificate
openssl x509 -noout -text -in "${ROOT}/certs/ca.cert.pem"

### Create the intermediate pair
INTERMEDIATE="${ROOT}/intermediate"
touch index.txt.attr
mkdir $INTERMEDIATE
cd $INTERMEDIATE
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
touch index.txt.attr
echo 1000 > serial

echo 1000 > "${INTERMEDIATE}/crlnumber"

#Create the Intermediate Key
cp "${BASE}/init/2d-intra-openssl.cnf" "${INTERMEDIATE}/openssl.cnf"

cd ${INTERMEDIATE}
cd $ROOT

openssl genrsa -aes256 \
	-out intermediate/private/intermediate.key.pem 4096

chmod 400 intermediate/private/intermediate.key.pem

# Create the intermediate certificate
echo "Create the intermediate certificate"
cd $ROOT
openssl req -config intermediate/openssl.cnf -new -sha256 \
	-key intermediate/private/intermediate.key.pem \
	-out intermediate/csr/intermediate.csr.pem 

cd $ROOT

openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem \
      -out intermediate/certs/intermediate.cert.pem

chmod 444 intermediate/certs/intermediate.cert.pem

# Verify intermediate certificate

openssl x509 -noout -text \
	-in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem \
	intermediate/certs/intermediate.cert.pem

cd $ROOT

cat intermediate/certs/intermediate.cert.pem \
      certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem
fi

# Create a private key
cd $ROOT
openssl genrsa -aes256 \
	-out "intermediate/private/${1}.key.pem" 4069

chmod 400 "intermediate/private/${1}.key.pem"

## Create a certificate
openssl req -config intermediate/openssl.cnf \
      -key "intermediate/private/${1}.key.pem" \
      -new -sha256 -out "intermediate/private/${1}.csr.pem"


# If the certificate is going to be used on a server,
# use the server_cert extension. If the certificate is 
# going to be used for user authentication, use the usr_cert extension.
# this is represented by $1 command line arg

cd $ROOT
openssl ca -config "${ROOT}/intermediate/openssl.cnf" \
      -extensions obj_cert -days 375 -notext -md sha256 \
      -in "${ROOT}/intermediate/private/${1}.csr.pem" \
      -out "${ROOT}/intermediate/certs/${1}.cert.pem" 

ls "${ROOT}/intermediate/certs/"
chmod 444 "${ROOT}/intermediate/certs/${1}.cert.pem"

cat intermediate/index.txt


## Verify the certificate
openssl x509 -noout -text \
      -in "intermediate/certs/${1}.cert.pem"

## Use the CA certificate chain to verify the new certificate has 
# a valid chain of trust
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
	"intermediate/certs/${1}.cert.pem"

#openssl rsa -in "intermediate/private/${1}.key.pem" -out "${1}.public" -pubout -outform PEM

#openssl dgst -sha256 -sign "intermediate/private/${1}.key.pem" -out "${3}.sign.txt.sha256" "${BASE}/${2}"
#openssl enc -base64 -in "${3}.sign.txt.sha256" -out "${3}.txt.sha256.base64" -p

exit
#openssl dgst -sha256 -sign my_private.key -out sign.txt.sha256 codeToSign.txt
#openssl enc -base64 -in sign.txt.sha256 -out sign.txt.sha256.base64

#openssl enc -base64 -d -in sign.txt.sha256.base64 -out sign.txt.sha256
#openssl dgst -sha256 -verify "${1}.public" -signature sign.txt.sha256 $2
