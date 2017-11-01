#!/bin/sh

NAME="gooey"

#Cleanup.
rm -f bin/*

rm /usr/local/bin/$NAME 2>/dev/null

echo "Cleanup done."
