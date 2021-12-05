#!/bin/bash

#
# install-unpriv 
# @param1 A destination directory that should be assumed not to exist.
#
# Script creates the bin, mail, and tmp directories and adds all
# security features to the mailer that do not require root privileges.
#

# Check if destination directory exists
# If exists, give an error message and exit
if [ -d "message-sys" ]; then
	echo "Error: destination directory exists. Run sudo make uninstall."
 	exit 1
fi


# Create the destination directory 
mkdir message-sys
cd message-sys
mkdir tmp
mkdir pub
mkdir priv
cd pub

# Secure tmp and mail prior to creation
# by preventing anyone from modifying, reading, writing
umask 777
mkdir tmp mail bin

# Give users, groups, others permission to read mail directory (444)
# Give users, groups, others permission to execute directory (111)
# Enabling all to cd into the directory as necessary
# Include sticky bit to prevent deletion
umask 000
chmod 1555 mail
