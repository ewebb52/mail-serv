#
# Makefile for 4181
#

CC  = gcc
CXX = g++

CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = -g 
LDLIBS = -lm 

.PHONY: install
install: 
	./install-unpriv.sh $(TREE)
	make all
	sudo ./install-priv.sh $(TREE)

.PHONY: all
all: mail-in mail-out

mail-in: mail-in.o list.o
	gcc -g -Wall mail-in.o list.o -o mail-in

list.o: list.c list.h
	gcc -g -Wall -c list.c

mail-in.o: mail-in.c list.h mail.h
	gcc -g -Wall -c mail-in.c

mail-out: mail-out.o mail.h
	gcc -g -Wall mail-out.o -o mail-out

mail-out.o: mail-out.c
	gcc -g -Wall -c mail-out.c

.PHONY: clean
clean:
	rm -f *.o *~ a.out core mail-in mail-out
	sudo ./uninstall-priv.sh $(TREE)
