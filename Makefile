CC  = gcc
CXX = g++

INCLUDES = -I./crypto-algorithms
CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = -g 
LDLIBS = -lm -lssl -lcrypto -ldl

.PHONY: default
default: server

server: server.c server.h handler.h

getcert:

end: 

changepw:

sendmsg: list.o list.h

list:

list.o: list.h

recvmsg:

cms_enc:

cms_dec:

TEST-getcert-post:

TEST-getcert-segfault:

TEST-changepw-post:

TEST-changepw-segfault:

test-driver:

hash-password: hash-password.o crypto-algorithms/sha256.o crypto-algorithms/aes.o
	gcc -g -Wall hash-password.o crypto-algorithms/sha256.o crypto-algorithms/aes.o -o hash-password

hash-password.o: hash-password.c 
	gcc -g -Wall -c hash-password.c

check-password: check-password.o crypto-algorithms/sha256.o crypto-algorithms/aes.o
	gcc -g -Wall check-password.o crypto-algorithms/sha256.o crypto-algorithms/aes.o -o check-password

check-password.o: check-password.c 
	gcc -g -Wall -c check-password.c

check-user:

../crypto-algorithms/sha256.o: ../crypto-algorithms/sha256.c ../crypto-algorithms/sha256.h

../crypto-algorithms/aes.o: ../crypto-algorithms/aes.c ../crypto-algorithms/aes.h

.PHONY: clean
clean:
	rm -f *.o *~ a.out core check-password hash-password server getcert changepw sendmsg recvmsg client check-user cms_enc cms_dec TEST-getcert-post TEST-changepw-post TEST-getcert-segfault TEST-changepw-segfault

.PHONY: all
all: server getcert changepw sendmsg recvmsg hash-password check-password check-user getcert changepw sendmsg recvmsg

.PHONY: install
install:
	sudo scripts/mailbox_gen.sh
	sudo scripts/install-unpriv.sh
	sudo scripts/install-priv.sh
	sudo scripts/run-CA-priv.exp
	sudo scripts/add-pass.sh
	sudo scripts/salt-hash.sh

.PHONY: uninstall
uninstall:
	rm -r ca
	rm -r message-sys
	

.PHONY: client
client:
	mkdir privkeys
	mkdir clientcsr
	make getcert changepw sendmsg recvmsg
	make test-driver
.PHONY: test
test:  
	make test-driver TEST-getcert-post TEST-changepw-post TEST-getcert-segfault TEST-changepw-segfault
