# Email System
Maria Kogan (mk4036)

## Files
```
create-tree.sh		        # Creates the directory tree
inputs/		                # All test inputs
test.sh                   # Test script
mail-in                   # Executable
mail-out                  # Executable
README.md                 # This file, explaining the project
Makefile                  # Makefile
```
## Usage
```
cd <some-dir>
./bin/mail-in

provide input...
^D

```
## Dependencies
```
apt-get install valgrind
```

## To Test
```
./create-tree <test-dir>
make clean
make DEST=<test-dir>/bin
cp test.sh <test-dir>
cd <test-dir>
./test.sh
```

## Attack Model
Attacker does not have access to run the mail-out executable independently, as indicated in the assignment spec.
Attacker does not have the ability to tamper with tmp/ directory, or mail/<some-rcpt> directories.
