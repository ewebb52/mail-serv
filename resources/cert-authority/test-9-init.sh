#!/bin/bash

echo "[ EXPECTED ERROR: num=9:certificate is not yet valid ]"
./run-cert-authority.sh
./sign-server.sh
./sign-not-before-cert.sh
