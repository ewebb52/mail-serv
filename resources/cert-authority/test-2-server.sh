#!/bin/bash

echo "Initializing server..."

openssl s_server -accept 443305 -cert root/ca/intermediate/certs/www.server.com.cert.pem -key root/ca/intermediate/private/www.server.com.key.pem -pass pass:tester -WWW -CAfile incomplete.cert.pem -Verify 100 -verify_return_error
