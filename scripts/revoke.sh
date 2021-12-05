# Team Valgrind
# Final - Security1

#!/bin/bash

HOME=$(pwd)
USER_CERT=$1

openssl ca -config $HOME/ca/intermediate/openssl.cnf -revoke $HOME/message-sys/priv/$USER_CERT/cert/$USER_CERT.cert.pem
openssl ca -config $HOME/ca/intermediate/openssl.cnf -gencrl -out $HOME/ca/intermediate/crl/intermediate.crl.pem
openssl crl -in $HOME/ca/intermediate/crl/intermediate.crl.pem -noout -text