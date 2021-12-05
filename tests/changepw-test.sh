#!/bin/bash
# Instructions: run from home folder EX: tests/changepw-test.sh

this=$(tr -dc 'a-zA-Z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_{|}~' < /dev/urandom | head -c100000)

########################### ./changepw tests #############################
echo "now testing ./changepw"

##### TEST INVALID USERS ######
echo ""
echo "######### TEST 1 ##########"
# Check invalid user
./TEST-changepw-segfault vegetaceous channelled_inexpressible localhost
echo ""
echo "######### TEST 2 ##########"
# Check valid user but bad password
./TEST-changepw-segfault vegetaceous channelled_in localhost
echo ""
echo "######### TEST 3 ##########"
# Check Sudo
./TEST-changepw-segfault sudo channelled_inexpressible localhost

####### TEST SEG FAULTS ########
echo ""
echo "######### TEST 4 ##########"
# Seg fault user
./TEST-changepw-segfault $this channelled_inexpressible localhost
echo ""
echo "######### TEST 5 ##########"
# Seg fault pass 
./TEST-changepw-segfault vegetocarbonaceous $this localhost
echo ""
echo "######### TEST 6 ##########"
# Seg fault port
./TEST-changepw-segfault vegetocarbonaceous channelled_inexpressible $this
echo ""
echo "######### TEST 7 ##########"
# Seg fault all
./TEST-changepw-segfault $this $this localhost

####### TEST BAD HEADERS ########
echo ""
echo "######### TEST 8 ##########"
# TEST POST rather than GET
./TEST-changepw-post vegetocarbonaceous channelled_inexpressible localhost
echo ""
echo "######### TEST 9 ##########"
# SUDO with POST
./TEST-changepw-post sudo channelled_inexpressible localhost


echo "end testing ./changepw"