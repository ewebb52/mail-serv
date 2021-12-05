#!/bin/bash

echo "[ EXPECTED ERROR: num=2: unable to get issuer certificate ]"
./incomplete-cert-list.sh
./tamper-ca-chain.sh
