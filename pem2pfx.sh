
OUT_PFX=$1
IN_KEY=$2
IN_CRT=$3
IN_CHAIN=$4

if [ -z "$IN_CHAIN" ]; then
	echo "Usage:  pem2pfx.sh  <out_pfx>  <in_key>  <in_crt>  <in_chain>"
	exit 1
fi

openssl pkcs12 -export -out $OUT_PFX -inkey $IN_KEY -in $IN_CRT -certfile $IN_CHAIN
