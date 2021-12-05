#!/bin/bash

echo "[ EXPECTED ERROR: num=10:certificate has expired ]"
./run-cert-authority.sh
./sign-server.sh
./sign-outdated-cert.sh

