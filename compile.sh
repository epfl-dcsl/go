#!/bin/sh

NAME="gooey"
CURRENT=`pwd`

# Compiling.
echo "Compiling..."
echo "........................."
cd src/
GOOS=linux GOARCH=amd64 ./strap.bash
cd ..
echo "Done."
echo "........................."