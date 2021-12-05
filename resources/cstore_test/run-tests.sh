#!/bin/bash

echo "[ Initiating Encrypted File Store Testers ]"
rm archive
cp backupfile0 file0
cp backupfile1 file1
#####################################
echo "[ Initiating Archive by Adding First File ]"
valgrind cstore add -p mypassword archive file0 &> tester.out


declare -i c=0;
declare -i e=2;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Adding Additional Files ]"
valgrind cstore add -p mypassword archive file1 &>> tester.out
valgrind cstore add -p mypassword archive file2 &>> tester.out

declare -i c=0;
declare -i e=2;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Listing Files ]"
valgrind cstore list archive &>> tester.out
cstore list archive &>> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi

cmp --silent list0.out tester.out || c=$((c + 1))

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Extracting File ]"
rm file0 # cannot extract if file exists in current dir...
valgrind cstore extract -p mypassword archive file0 &> tester.out 

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cmp -s file0 backupfile0; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Deleting File ]"
valgrind cstore delete -p mypassword archive file1 &> tester.out

declare -i c=0;
declare -i e=2;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out

#####################################
echo "[ Re-Listing Files ]"
valgrind cstore list archive &> tester0.out
cstore list archive &> tester1.out

declare -i c=0;
declare -i e=3;
if cat tester0.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester0.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cmp -s list1.out tester1.out; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester0.out
cat tester1.out
rm tester0.out
rm tester1.out


#####################################
echo "[ Extracting Deleted File ]"
valgrind cstore extract -p mypassword archive file1 &> tester.out

rm file1 # cannot extract if file exists in current dir...
valgrind cstore extract -p mypassword archive file1 &> tester.out 

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "No such file in archive"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out
cp backupfile1 file1 #retrieve file1

#####################################
echo "[ Re-Adding Deleted File ]"
valgrind cstore add -p mypassword archive file1 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Added to archive"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Adding Duplicate File ]"
valgrind cstore add -p mypassword archive file2 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "File already exists in archive"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ List Command Run On Invalid Archive ]"
valgrind cstore list maliciousarchive &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Archive does not exist"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Extracting from Invalid Archive ]"

rm file1
valgrind cstore extract -p mypassword maliciousarchive file1 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Archive does not exist"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out
cp backupfile1 file1

#####################################
echo "[ Deleting from an Invalid Archive ]"

valgrind cstore delete -p mypassword maliciousarchive file1 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Archive does not exist"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
	cat tester.out
fi

cat tester.out
rm tester.out


#####################################
echo "[ Adding an Invalid File ]"

valgrind cstore add -p mypassword archive nonexistantfile &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "No such file or directory"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Extracting an Invalid File ]"

valgrind cstore extract -p mypassword archive nonexistant &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "No such file in archive"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
	cat tester.out
fi

cat tester.out
rm tester.out


#####################################
echo "[ Extracting a File That Exists in Directory (should not overwrite) ]"
cp backupfile1 file1
valgrind cstore extract -p mypassword archive file1 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Cannot extract to specified path"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out

#####################################
echo "[ DELETE Run On Invalid File ]"

valgrind cstore delete -p mypassword archive nonexistant &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "File not found in archive"; then
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
cat tester.out
fi

cat tester.out
rm tester.out


#####################################
echo "[ File Not Provided when Adding ]"

valgrind cstore add -p mypassword archive &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "usage"; then # produced prompt
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ File Not Provided when Extracting ]"

valgrind cstore extract -p mypassword archive &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "usage"; then # produced prompt
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ File Not Provided on DELETE ]"

valgrind cstore delete -p mypassword archive &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "usage"; then # produced prompt
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ List a Malicious Archive ]"

valgrind cstore list malicious-archive &> tester.out

declare -i c=0;
declare -i e=2;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out


#####################################
echo "[ Integrity Check on Malicious Archive ]"

cp archive backuparchive
cp malicious-archive archive

valgrind cstore add -p mypassword malicious-archive file1 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Integrity of archive has been compromised"; then
    c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
cp backuparchive archive 
rm tester.out

#####################################
echo "[ Malicious Password Inputted To Archive ]"

valgrind cstore add -p maliciouspassword archive file3 &> tester.out

declare -i c=0;
declare -i e=3;
if cat tester.out | grep -q "no leaks are possible"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "0 errors from 0 contexts"; then
    c=$((c + 1))
fi
if cat tester.out | grep -q "Integrity of archive has been compromised"; then 
	c=$((c + 1))
fi

if [ $c -eq $e ]; then
	echo "  PASS"
else echo "  FAIL"
fi

cat tester.out
rm tester.out







# reset environment for later reruns
rm archive
cp backupfile0 file0
cp backupfile1 file1
