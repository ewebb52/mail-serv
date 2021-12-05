#!/bin/bash

#####################################
echo "[ Testing Random Malloc Failures ]"

for i in {1..3}; do
valgrind ../cstore/cstore add -p mypassword archive file0 file1 file2 >> mtest.out
valgrind ../cstore/cstore list archive >> mtest.out
rm file0 file1 >> mtest.out
valgrind ../cstore/cstore extract -p mypassword archive file0 file1 >> mtest.out
valgrind ../cstore/cstore delete -p mypassword archive file1 file0 >> mtest.out
valgrind ../cstore/cstore list archive  >> mtest.out
valgrind ../cstore/cstore extract -p mypassword archive file1  >> mtest.out
rm file1 # cannot extract if file exists in current dir...
valgrind ../cstore/cstore extract -p mypassword archive file1 >> mtest.out
valgrind ../cstore/cstore add -p mypassword archive file1 >> mtest.out
valgrind ../cstore/cstore add -p mypassword archive file2 file1 >> mtest.out
valgrind ../cstore/cstore list maliciousarchive >> mtest.out
valgrind ../cstore/cstore extract -p mypassword maliciousarchive file1 file2 >> mtest.out
valgrind ../cstore/cstore delete -p mypassword maliciousarchive file1 file2 >> mtest.out
valgrind ../cstore/cstore add -p mypassword archive nonexistantfile >> mtest.out
valgrind ../cstore/cstore extract -p mypassword archive nonexistant  >> mtest.out
valgrind ../cstore/cstore extract -p mypassword archive file1 file3 >> mtest.out
valgrind ../cstore/cstore delete -p mypassword archive nonexistant >> mtest.out
valgrind ../cstore/cstore add -p mypassword archive >> mtest.out
valgrind ../cstore/cstore extract -p mypassword archive >> mtest.out
valgrind ../cstore/cstore delete -p mypassword archive >> mtest.out
valgrind ../cstore/cstore list malicious-archive >> mtest.out
valgrind ../cstore/cstore add -p mypassword malicious-archive file1 file0 >> mtest.out
valgrind ../cstore/cstore add -p maliciouspassword archive file3 file2 >> mtest.out
done;

#####################################

rm archive
