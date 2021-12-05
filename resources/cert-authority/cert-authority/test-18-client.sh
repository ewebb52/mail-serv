#!/bin/bash

echo "Connecting self-signed client..."
sleep 3
openssl s_client -connect localhost:443301 -cert malicious-root/ca/certs/ca.cert.pem -key malicious-root/ca/private/ca.key.pem -pass pass:tester -CAfile root/ca/intermediate/certs/ca-chain.cert.pem 

