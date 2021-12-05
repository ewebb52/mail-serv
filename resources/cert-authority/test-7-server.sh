#!/bin/bash

echo "Initializing server..."
openssl s_server -accept 111117 -cert root/ca/intermediate/certs/www.server.com.cert.pem  -key root/ca/intermediate/private/www.server.com.key.pem -pass pass:tester -WWW -CAfile root/ca/intermediate/certs/ca-chain.cert.pem -Verify 100 -verify_return_error
