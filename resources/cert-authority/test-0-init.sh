#!/bin/bash

echo "[ EXPECTED ERROR: num=0:ok ]"
./run-cert-authority.sh
./sign-server.sh
./sign-client-cert.sh

