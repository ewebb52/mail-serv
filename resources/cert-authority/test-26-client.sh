#!/bin/bash

echo "Connecting client..."
sleep 5

echo "GET /test/tell-me-a-joke.txt HTTP/1.1\r\n\r\n" | openssl s_client -connect localhost:111111 -cert root/ca/intermediate/certs/www.client-malicious.com.cert.pem -key root/ca/intermediate/private/www.client-malicious.com.key.pem -pass pass:tester -CAfile root/ca/intermediate/certs/ca-chain.cert.pem -ign_eof -verify_return_error
