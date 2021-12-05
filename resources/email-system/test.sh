#!/bin/bash

while IFS= read -r line
do
        mkdir "mail/${line}"
done < "../words.txt"

cp ../inputs/* inputs/

for i in inputs/*
do
	cat $i
	./bin/mail-in <$i
done
