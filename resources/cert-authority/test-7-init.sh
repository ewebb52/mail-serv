#!/bin/bash

echo "[ EXPECTED ERROR: num=7: certificate signature failure]"
./run-cert-authority.sh
./sign-server.sh
./sign-client-cert.sh
./tamper-client-cert.sh
