#!/bin/bash

unset ln lnr
while read -r; do
    ((lnr++))
    case "$REPLY" in
        *BEGIN*) ln="$lnr";;
    esac
done < root/ca/intermediate/certs/ca-chain.cert.pem 
echo $ln

SECONDV=1
COUNT=`expr $ln - $SECONDV`

sed -n "1, ${COUNT}p" root/ca/intermediate/certs/ca-chain.cert.pem > incomplete.cert.pem


