#!/bin/bash

BASE="$PWD"
ROOT="${PWD}/root/ca"
INIT="${PWD}/init"

### Reset Enviro
if [ -d "root" ]; then rm -Rf "root"; fi

### Create the root pair

# Prepare the directory
mkdir root
cd root
mkdir ca

cd $ROOT
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# Prepare the config file
cp "${BASE}/init/openssl.cnf" $ROOT

# Create the root key
cd $ROOT
openssl genrsa -aes256 -out private/ca.key.pem -passout pass:tester 4096 

# Create the root certificate
cd $ROOT
openssl req -config "${ROOT}/openssl.cnf" -key "${ROOT}/private/ca.key.pem" -passin pass:tester -new -x509 -out certs/ca.cert.pem -passout pass:tester 
 
chmod 444 certs/ca.cert.pem

# Verify the root certificate
openssl x509 -noout -text -in "${ROOT}/certs/ca.cert.pem" -passin pass:tester

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
cp "${BASE}/init/intra-openssl.cnf" "${INTERMEDIATE}/openssl.cnf"
cp "${BASE}/init/s-intra-openssl.cnf" "${INTERMEDIATE}/s-intra-openssl.cnf"
cp "${BASE}/init/c-intra-openssl.cnf" "${INTERMEDIATE}/c-intra-openssl.cnf"
cp "${BASE}/init/cs-intra-openssl.cnf" "${INTERMEDIATE}/cs-intra-openssl.cnf"
cd ${INTERMEDIATE}
cd $ROOT

openssl genrsa -aes256 \
	-out intermediate/private/intermediate.key.pem -passout pass:tester 4096

chmod 400 intermediate/private/intermediate.key.pem

# Create the intermediate certificate
echo "Create the intermediate certificate"
cd $ROOT
openssl req -config intermediate/openssl.cnf -new -sha256 \
	-key intermediate/private/intermediate.key.pem -passin pass:tester \
	-out intermediate/csr/intermediate.csr.pem -passout pass:tester

cd $ROOT
cd $INTERMEDIATE
cd $ROOT

openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem -passin pass:tester \
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

