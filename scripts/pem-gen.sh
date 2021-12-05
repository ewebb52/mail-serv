#!/bin/bash

HOME=$(pwd)
USER=$1
USER_CERT=$2
USER_KEY=$3

cat $USER_CERT > $USER.combined.pem
cat $USER_KEY >> $USER.combined.pem
