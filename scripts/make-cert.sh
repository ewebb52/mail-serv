#!/bin/bash

#cd ..

HOME=$(pwd)
echo $HOME
USER_CERT=$1

echo ""
echo "Creating user certificate"
echo ""

#added nodes
#openssl req -config ca/intermediate/opensslclient.cnf -key $HOME/pubkeys/$USER_CERT.pubkey.pem -new -sha256 -out ca/intermediate/csr/$USER_CERT.csr.pem -nodes

openssl ca -config ca/intermediate/opensslclient.cnf -extensions usr_cert -days 375 -notext -md sha256 -in $HOME/message-sys/tmp/$USER_CERT.csr.pem -out ca/intermediate/certs/$USER_CERT.cert.pem

#chmod 444 intermediate/certs/$USER.cert.pem
chmod 644 ca/intermediate/certs/$USER_CERT.cert.pem

echo ""
echo "verify user certificate"
echo ""

openssl x509 -noout -text -in ca/intermediate/certs/$USER_CERT.cert.pem
openssl verify -CAfile ca/intermediate/certs/ca-chain.cert.pem ca/intermediate/certs/$USER_CERT.cert.pem

echo ""
echo "end of generating client cert."

mv ca/intermediate/certs/$USER_CERT.cert.pem $HOME/message-sys/priv/$USER_CERT/cert/

exit 1
