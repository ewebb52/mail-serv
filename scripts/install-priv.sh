#!/bin/bash

#
# install-priv
# @param1 A destination directory that should be assumed to exist.
#
# Script adds all security features to the mailer 
# that do require root privileges.
#

input=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")

# Per office hours, put mail-in, mail-out executables in a single
# Group, and create an owner for this group.
# Attackers are not permitted to join this group using sudo
# In case attacker creates group prior to installation, delete now
groupdel mail-group
addgroup mail-group
useradd mail-owner

# Unique user has ownership of executables, bin, and tmp directories
# Unique group has ownership of executables, bin, and tmp directories
chown mail-owner:mail-group mail-in mail-out "message-sys/bin" "message-sys/tmp" "message-sys/mail"

umask 000
chmod 770 -R "message-sys/tmp"
chmod 775 -R "message-sys/bin"
#chmod 2775 mail-in
#chmod 2770 mail-out 		# setgid = 2
chmod 770 -R "message-sys/tmp"
umask 777
touch "message-sys/tmp/saveme"
umask 000

#mv mail-out mail-in "message-sys/bin/"
#chattr -R +i "message-sys/bin"

# Set ownership of directories and inner files to user
# Direct ownership to ensure only user can run ls dirname/
# Make sure that the mailboxes are writable by some group
# (which you can create with the addgroup command)

# Set Unix Initial File Permissions to prevent race conditions
# Only giving user access to their directory.
# In loop: change ownership of the file, change permissions to allow
# Owners to access their own directories in all modes

umask 777

# Pub message system
cd message-sys
cd pub
cd mail
for line in ${input[@]}
do
	mkdir "${line}"
	sudo chown -R  "${line}" "${line}/" 
	umask 000
	sudo chmod 700 "${line}"
	sudo chgrp -R mail-group "${line}/" 
	sudo chmod -R 770 "${line}/" 
	umask 777
done

# Priv message system
cd ..
cd ..
cd priv
for line in ${input[@]}
do
	mkdir "${line}"
	cd "${line}"
	mkdir pass
	mkdir cert
	sudo chmod 700 *
	cd ..
	sudo chmod 700 "${line}"
done

cd ..
sudo chown -R $SUDO_USER priv

umask 077
exit 0
