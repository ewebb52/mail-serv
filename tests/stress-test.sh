#!/bin/bash

read -p "Did you initialize the server using sudo ./server?" yn
    case $yn in
        [Yy]* ) continue;;
        [Nn]* ) exit;;
    esac

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "clients request certificates"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./getcert untranquil bespoke_supplants localhost
sleep 1
./getcert reinsure Hammett_Biden\'s localhost
sleep 1
./getcert corector quadruplet_strawed localhost
sleep 1
./getcert durwaun hamlet_laudably localhost
sleep 1
./getcert anthropomorphologically likelihoods_hoarsely localhost
sleep 1
./getcert addleness Cardin_pwns localhost
sleep 1
./getcert polypose lure_leagued localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "one client re-requests certificate"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./getcert corector quadruplet_strawed localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client changes password and tries to re-log in with old password"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./changepw polypose lure_leagued newpassword localhost
sleep 1

./changepw polypose lure_leagued newpassword localhost
sleep 1

echo "What do you call an excavated pyramid?" > message
echo "Unencrypted." >> message

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client with invalid certificate tries to send a message"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./sendmsg repine tests/malicious.cert.pem tests/malicious.privkey.pem message localhost endoscopic
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client sends a message to clients who do not have certificates"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./sendmsg reinsure reinsure.cert.pem privkeys/reinsure.privkey.pem message localhost exilic
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client sends a message to a malicious client"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./sendmsg reinsure reinsure.cert.pem privkeys/reinsure.privkey.pem message localhost ../durwaun
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client sends a message to clients"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./sendmsg reinsure reinsure.cert.pem privkeys/reinsure.privkey.pem message localhost untranquil corector durwaun analects addleness
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client changes password before receiving pending messages"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./changepw untranquil newpassword bespoke_supplants localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client checks messages"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./recvmsg durwaun durwaun.cert.pem privkeys/durwaun.privkey.pem localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client changes password after sending message"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./changepw reinsure Hammett_Biden\'s newpassword localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client tries to decrypt message after sender changes password"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./recvmsg corector corector.cert.pem privkeys/corector.privkey.pem localhost
sleep 1

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "client checks empty mailbox"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
./recvmsg durwaun durwaun.cert.pem privkeys/durwaun.privkey.pem localhost
sleep 1

