#!/bin/bash

echo "[ EXPECTED ERROR: num=20:  unable to get local issuer certificate ]"
./incomplete-cert-list.sh
