Security Homework 4
Julia Kalimova
jk4102

Files in submission: Makefile	README.txt	install-priv	install-unpriv	mail-in.cpp	mail-in.h	mail-out.cpp	mail-out.h	mail_utils.cpp	mail_utils.h run_tests.sh create_tree.sh inputs directory, outputs directory

1. Unchanged from Homework 3 solution: mail-in.cpp mail-in.h   mail-out.cpp    mail-out.h  mail_utils.cpp  mail_utils.h run_tests.sh create-tree.sh inputs directory, outputs directory
	inputs, outputs, create-tree.sh, run_tests.sh included for hw3 completeness.

2. Makefile - based on Homework 3 solution's Makefile, slightly modified so that make install runs the install-unpriv and install-priv scripts

3. install-unpriv - based on Homework 3 solutions' create-tree.sh, but no longer creates an inputs directory

4. install-priv - is run with sudo and sets the appropriate ownership and permissions for the mailboxes and mail-in, mail-out

5. README.txt - this file :)

The privileged script install-priv must be run with sudo in order to execute chmod, chown, useradd, addgroup, usermod.
Each mailbox is owned by its correspoding user; all mailboxes belong to the additionally created group mailer.
mail-in and mail-out belong to the additionally created user mailagent and group mailer.
The mailbox permissions are set so that the emails can be read and overwritten/deleted only by the mailbox's owner and group.
This means that only the corresponding user and mail-out can write to the mailbox.
Permissions on mail-in, mail-out are set using setgid so that only the group mailer (i.e. only mail-in) can invoke mail-out,
and no one outside mailer group can write or delete mail-in, mail-out.

To set up the directory tree with correct permissions and place the executables in the tree's bin:

	Compile .cpp code, create mail directory tree, copy executables to tree's bin, setup permissions: 
		make install TREE=dest

	The above command compiles the C++ code,
	calls install-unpriv with argument dest, which creates a directory dest and sets up the mail tree inside dest,
	moves the executables to dest/bin,
	and calls sudo install-unpriv with argument dest to set up the proper permissions.


Resulting file & directory permissions for reference:

dest:
total 20
drwxrwxr-x  5 jk4102 jk4102 4096 Nov 18 04:38 .
drwxrwxr-x  4 jk4102 jk4102 4096 Nov 18 04:38 ..
drwxrwxr-t  2 jk4102 jk4102 4096 Nov 18 04:38 bin
drwxrwxr-t 37 jk4102 jk4102 4096 Nov 18 04:38 mail
drwxrwxr-t  2 jk4102 jk4102 4096 Nov 18 04:38 tmp
dest/bin:
total 1276
drwxrwxr-t 2 jk4102    jk4102   4096 Nov 18 04:38 .
drwxrwxr-x 5 jk4102    jk4102   4096 Nov 18 04:38 ..
-rwxrwsr-x 1 mailagent mailer 665792 Nov 18 04:38 mail-in
-rwxrws--- 1 mailagent mailer 626824 Nov 18 04:38 mail-out
dest/mail:
total 148
drwxrwxr-t 37 jk4102                  jk4102 4096 Nov 18 04:38 .
drwxrwxr-x  5 jk4102                  jk4102 4096 Nov 18 04:38 ..
drwxrwx--T  2 addleness               mailer 4096 Nov 18 04:38 addleness
drwxrwx--T  2 analects                mailer 4096 Nov 18 04:38 analects
drwxrwx--T  2 annalistic              mailer 4096 Nov 18 04:38 annalistic
... same for all mailboxes
For files inside mailbox:
-rw-rw-r--  1 jk4102   mailer  549 Nov 18 04:49 00001

dest/tmp:
total 8
drwxrwxr-t 2 jk4102 jk4102 4096 Nov 18 04:38 .
drwxrwxr-x 5 jk4102 jk4102 4096 Nov 18 04:38 ..





-------------------------------------------------------------------------------
Homework 3 Solutions README for reference:

Security HW 3: Email System

######################################
###### 0. DEPENDANCIES ####### #######
######################################
sudo apt-get install build-essential
sudo apt-get update
sudo apt-get install valgrind
sudo apt-get install icdiff

######################################
###### I. SOURCE TREE CONTENTS #######
######################################

This folder contains the following files:

    1.  mail-in.cpp:    The source code for compiling the mail-in program.
    2.  mail-in.h:      Accompanying mail-in header file.
    3.  mail-out.cpp:   The source code for compiling the mail-out program.
    4.  mail-out.h:     Accompanying mail-out header file.
    5.  mail_utils.cpp: The utilities file for various helper functions for both mail-in and mail-out.
    6.  mail_utils.h:   Accompanying mail_utils header file.
    7.  Makefile:       Allows you to easily make mail-in and mail-out executables and install.
    8.  README.txt:     This file!
    9:  create-tree.sh: The bash script for creating the mail system directory
    10. run_tests.sh:   Runs all the tests in inputs/ printing error messages to stderr when appropriate.

And two directories:

    1. inputs: Includes all test input files, labeled as specified (e.g. 00001, 00002, ...).
    2. outputs: Contains an example of what the mail directory "should" look like after each test.
               

#################################
###### II. HOW TO EXECUTE #######
#################################


1. Create the mail system directory:
    $ ./create-tree.sh <mail system name>

2. Make and install the executables to the mail system bin subdirectory:
    $ make install TREE=<mail system name>

3. Run the tests:
    $ ./run_tests.sh <mail system name>

