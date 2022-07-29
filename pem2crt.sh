#!/bin/sh

IN_PEM=$1
OUT_CRT=$2 

if [ -z "$IN_PEM" -o -z "$OUT_CRT" ]; then
        echo "Usage:  pem2txt.sh  <in_pem> <out_crt>"
        exit 1
fi

openssl x509 -outform der -in $IN_PEM -out $OUT_CRT
