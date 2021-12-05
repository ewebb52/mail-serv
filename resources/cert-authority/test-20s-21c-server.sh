#!/bin/bash

echo "Initializing server with an incomplete certificate chain..."

openssl s_server -accept 443320 -cert root/ca/intermediate/certs/www.server.com.cert.pem  -key root/ca/intermediate/private/www.server.com.key.pem -pass pass:tester -WWW  -Verify 100 -verify_return_error
