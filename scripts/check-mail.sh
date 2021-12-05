#!/bin/bash

DIR=$1
# echo $DIR

if [ -n "$(ls -A $DIR)" ]; then
   # Not empty
   echo "Not empty"
   exit 1
else
   # Empty
   echo "Empty"
   exit 0
fi