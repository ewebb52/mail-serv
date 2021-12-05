#!/bin/bash

echo "Connecting client..."
sleep 2

openssl s_client -connect localhost:111127 -cert root/ca/intermediate/certs/www.client.com.cert.pem -key root/ca/intermediate/private/www.client.com.key.pem -pass pass:tester -CAfile root/ca/intermediate/certs/ca-chain.cert.pem
