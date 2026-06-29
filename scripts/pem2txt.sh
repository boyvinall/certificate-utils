#!/bin/sh

IN_PEM=$1

if [ -z "$IN_PEM" ]; then
        echo "Usage:  pem2txt.sh  <in_pem>"
        exit 1
fi

openssl x509 -in $IN_PEM -text
