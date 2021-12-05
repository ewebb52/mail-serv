#!/bin/bash
# Instructions: run from home folder EX: tests/getcert-test.sh

this=$(tr -dc 'a-zA-Z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_{|}~' < /dev/urandom | head -c100000)

########################### ./getcert tests #############################
echo "Testing ./getcert"

##### TEST INVALID USERS ######
echo ""
echo "######### TEST 1 ##########"
# Check invalid user
./TEST-getcert-segfault vegetaceous channelled_inexpressible localhost
##### TEST INVALID USERS ######
echo ""
echo "######### TEST 2 ##########"
# Check valid user but bad password
./TEST-getcert-segfault vegetocarbonaceous channelled_in localhost
echo ""
echo "######### TEST 3 ##########"
# Check sudo
./TEST-getcert-segfault sudo channelled_inexpressible localhost

####### TEST SEG FAULTS ########
echo ""
echo "######### TEST 4 ##########"
# Seg fault user
./TEST-getcert-segfault $this channelled_inexpressible localhost
echo ""
echo "######### TEST 5 ##########"
# Seg fault pass 
./TEST-getcert-segfault vegetocarbonaceous $this localhost
echo ""
echo "######### TEST 6 ##########"
# Seg fault port
./TEST-getcert-segfault vegetocarbonaceous channelled_inexpressible $this
echo ""
echo "######### TEST 7 ##########"
# Seg fault all
./TEST-getcert-segfault $this $this localhost


####### TEST BAD HEADERS ########
echo ""
echo "######### TEST 8 ##########"
# TEST POST rather than GET
./TEST-getcert-post vegetocarbonaceous channelled_inexpressible localhost
echo ""
echo "######### TEST 9 ##########"
# SUDO with POST
./TEST-getcert-post sudo channelled_inexpressible localhost


echo "end testing ./getcert"