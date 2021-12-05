CC  = gcc
CXX = g++

INCLUDES = -I../crypto-algorithms
CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = -g 
LDLIBS = -lm 

.PHONY: default
default: cstore
cstore: cstore.o ../crypto-algorithms/sha256.o ../crypto-algorithms/aes.o
	gcc -g -Wall cstore.o ../crypto-algorithms/sha256.o ../crypto-algorithms/aes.o -o cstore 

cstore.o: cstore.c cstore.h
	gcc -g -Wall -c cstore.c

../crypto-algorithms/sha256.o: ../crypto-algorithms/sha256.c ../crypto-algorithms/sha256.h

../crypto-algorithms/aes.o: ../crypto-algorithms/aes.c ../crypto-algorithms/aes.h

.PHONY: clean
clean:
	rm -f *.o *~ a.out core cstore

.PHONY: all
all: clean cstore

.PHONY: install
install:
	install -m 557 cstore /usr/bin/cstore

.PHONY: test
test:
	chmod u+x ../cstore_test/run-tests.sh && cd ../cstore_test/ && ./run-tests.sh
	make clean
	gcc -g -Wall -c cstore.c -DMALICIOUS
	gcc -g -Wall cstore.o ../crypto-algorithms/sha256.o ../crypto-algorithms/aes.o -DMALICIOUS -o cstore
	chmod u+x ../cstore_test/malicious-malloc.sh && cd ../cstore_test/ && ./malicious-malloc.sh
	make clean
	
