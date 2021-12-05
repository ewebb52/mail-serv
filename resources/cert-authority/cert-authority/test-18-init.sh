#!/bin/bash

echo "[ EXPECTED ERROR: num=18:self signed certificate ]"
./run-cert-authority.sh
./sign-server.sh
./self-signed-client.sh

