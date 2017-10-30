#!/bin/sh

NAME="gooey"
DIR="../go-linux-amd64-bootstrap/"
FILE="../go-linux-amd64-bootstrap.tbz"

#Cleanup.
if [ -d "$DIR" ]; then
	rm -rf $DIR
fi

if [ -f "$FILE" ]; then
	rm $FILE
fi

rm /usr/local/bin/$NAME 2>/dev/null

echo "Cleanup done."
