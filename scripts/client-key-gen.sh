#!/bin/bash

# PARAMS: USER_NAME

#HOME=$(pwd)

#echo ""
echo "Creating client private key"
#echo ""
openssl genrsa -out privkeys/$1.privkey.pem 2048

#echo ""
echo "Creating client public key"
#echo ""
openssl rsa -in privkeys/$1.privkey.pem -outform PEM -pubout -out $1.pubkey.pem 

echo "Creating client CSR"
openssl req -new -key privkeys/$1.privkey.pem -out clientcsr/$1.csr.pem -subj "/C=US/ST=NY/L=./O=Global Security/OU=IT Department/CN=$1@columbia.edu"

