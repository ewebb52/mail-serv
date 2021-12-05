#!/bin/bash

CERT="root/ca/intermediate/certs/www.client.com.cert.pem"
MCERT="root/ca/intermediate/certs/www.malicious-client.com.cert.pem"
FOOTER="-----END CERTIFICATE-----"

CERTLEN=$(stat -c%s "$CERT")
FOOTLEN=${#FOOTER}
COUNT="$(( $CERTLEN - $FOOTLEN -5 ))"
dd bs=1 count=$COUNT if=$CERT of=$MCERT

echo a0= >> $MCERT
echo $FOOTER >> $MCERT

cat $CERT
cat $MCERT

