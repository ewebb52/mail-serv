#!/bin/bash

echo "[ EXPECTED ERROR: num=26:unsupported certificate purpose ]"
./run-cert-authority.sh
./sign-server.sh
./sign-client-server-cert.sh

