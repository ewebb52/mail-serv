# Email System

## Files
```
install-priv.sh			# Provides proper permissions to executables, directories, and files
install-unpriv.sh		# Create all of the subdirectories
uninstall-priv.sh		# Removes all creted users, groups, directories
mail-in                  	# Executable
mail-out                  	# Executable
README.md                 	# This file, explaining the project
Makefile                  	# Makefile
```

## Installation
```
make install TREE=<test-dir> # Performs all installations

```

## Usage
```
cd <test-dir>
./bin/mail-in

provide input...
^D

```
## Cleanup
 
```
make clean TREE=<test-dir>   # Removes all creted users, groups, directories
```

## Security Architecture
### Groups and Users
```
mail-group                    # additional group
mail-owner                    # additional user
```
### Program Privileges
```
-rwxrwsr-x mail-owner mail-group mail-in*               # owner, group can write. owner, group, others can read, execute. immutable.
-rwxrws--- mail-owner mail-group mail-out*              # owner, group can read, write, execute. others have no permissions. immutable.
```

### Permissions
```
drwxrwxr-x  bin/                    # owner (mail-owner) can read, write, execute. group (mail-group) can read, write, execute. others can execute.
dr-xr-xr-t  mail/                   # owner (mail-owner) can read, execute. group (mail-group) can read, execute. others can read.
                                    # directory is sticky (the owner of the directory or the root user to delete or rename the file).
drwxrwx---  tmp/                    # owner (mail-owner) can read, write, execute. group (mail-owner) can read, write, execute. others have no permissions.
drwxrwx---  mail/<mailbox>          # owner (usr) can read, write, execute. group (mail-group) can read, write, execute. others have no permissions.
```
