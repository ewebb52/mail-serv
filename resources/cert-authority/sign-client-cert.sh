#!/bin/bash
  
BASE="$PWD"
ROOT="${PWD}/root/ca"
INIT="${PWD}/init"
PASS="pass:tester"

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

