#!/bin/bash

BASE="$PWD"
ROOT="${PWD}/root/ca"
INIT="${PWD}/init"
PASS="pass:tester"

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
openssl genrsa -aes256 -out private/ca.key.pem -passout $PASS

# Create the root certificate
cd $ROOT
openssl req -config "${ROOT}/openssl.cnf" -key "${ROOT}/private/ca.key.pem" -passin $PASS -new -x509 -out certs/ca.cert.pem -passout $PASS
 
chmod 444 certs/ca.cert.pem

# Verify the root certificate
openssl x509 -noout -text -in "${ROOT}/certs/ca.cert.pem" -passin $PASS

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

cd ${INTERMEDIATE}
cd $ROOT

openssl genrsa -aes256 \
	-out intermediate/private/intermediate.key.pem -passout $PASS 4096

chmod 400 intermediate/private/intermediate.key.pem

# Create the intermediate certificate
echo "Create the intermediate certificate"
cd $ROOT
openssl req -config intermediate/openssl.cnf -new -sha256 \
	-key intermediate/private/intermediate.key.pem -passin $PASS \
	-out intermediate/csr/intermediate.csr.pem -passout $PASS

cd $ROOT
cd $INTERMEDIATE
cd $ROOT

openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem -passin $PASS \
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
cp intermediate/certs/ca-chain.cert.pem intermediate/certs/ca-chain-incomplete.cert.pem

echo "Now appending server certificate to the incomplete chain"

## Create a key
cd $ROOT
openssl genrsa -aes256 \
      -out intermediate/private/www.server.com.key.pem -passout $PASS 4069

chmod 400 intermediate/private/www.server.com.key.pem

## Create a certificate
openssl req -config intermediate/s-intra-openssl.cnf \
      -key intermediate/private/www.server.com.key.pem -passin $PASS \
      -new -sha256 -out intermediate/csr/www.server.com.csr.pem -passout $PASS


# If the certificate is going to be used on a server,
# use the server_cert extension. If the certificate is 
# going to be used for user authentication, use the usr_cert extension.
# this is represented by $1 command line arg

cd $ROOT
openssl ca -config "${ROOT}/intermediate/s-intra-openssl.cnf" \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in "${ROOT}/intermediate/csr/www.server.com.csr.pem" -passin $PASS \
      -out "${ROOT}/intermediate/certs/www.server.com.cert.pem"

ls "${ROOT}/intermediate/certs/"
chmod 444 "${ROOT}/intermediate/certs/www.server.com.cert.pem"

cat intermediate/index.txt


## Verify the certificate
openssl x509 -noout -text \
      -in intermediate/certs/www.server.com.cert.pem

## Use the CA certificate chain to verify the new certificate has 
# a valid chain of trust
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/www.server.com.cert.pem

#cp intermediate/certs/ca-chain.cert.pem $BASE
#cp "${ROOT}/intermediate/certs/www.example.com.cert.pem" $BASE
#cp intermediate/private/www.example.com.key.pem $BASE

# You can now either deply your new certificate or distribute it
# The files that need to be available to the server are:
# - ca-chain.cert.pem
# - www.example.com.key.pem
# - www.example.com.cert.pem

# A third-party, however, can instead create their own private key 
# and certificate signing request (CSR) without revealing their private 
# key to you. They give you their CSR, and you give back a signed 
# certificate. In that scenario, skip the genrsa and req commands.

## Create a key
cd $ROOT
openssl genrsa -aes256 \
      -out intermediate/private/www.client.com.key.pem -passout $PASS 4069

chmod 400 intermediate/private/www.client.com.key.pem

## Create a certificate
openssl req -config intermediate/c-intra-openssl.cnf \
      -key intermediate/private/www.client.com.key.pem -passin $PASS \
      -new -sha256 -out intermediate/csr/www.client.com.csr.pem  -passout $PASS


# If the certificate is going to be used on a server,
# use the server_cert extension. If the certificate is
# going to be used for user authentication, use the usr_cert extension.
# this is represented by $1 command line arg

cd $ROOT
openssl ca -config "${ROOT}/intermediate/c-intra-openssl.cnf" \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in "${ROOT}/intermediate/csr/www.client.com.csr.pem" -passin $PASS \
      -out "${ROOT}/intermediate/certs/www.client.com.cert.pem"

ls "${ROOT}/intermediate/certs/"
chmod 444 "${ROOT}/intermediate/certs/www.client.com.cert.pem"

cat intermediate/index.txt


## Verify the certificate
openssl x509 -noout -text \
      -in intermediate/certs/www.client.com.cert.pem

## Use the CA certificate chain to verify the new certificate has
# a valid chain of trust
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/www.client.com.cert.pem

# You can now either deply your new certificate or distribute it
# The files that need to be available to the server are:
# - ca-chain.cert.pem
# - www.example.com.key.pem
# - www.example.com.cert.pem

# A third-party, however, can instead create their own private key
# and certificate signing request (CSR) without revealing their private
# key to you. They give you their CSR, and you give back a signed
# certificate. In that scenario, skip the genrsa and req commands.

# DO diff of the two chains here ....
# comm -3 intermediate/certs/ca-chain-incomplete.cert.pem intermediate/certs/ca-chain.cert.pem > difference
# difference > intermediate/certs/ca-chain.cert.pem

