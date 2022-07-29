
IN_PFX=$1
OUT_CRT=$2

if [ -z "$OUT_CRT" ]; then
	echo "Usage:  pfx2pem.sh  <in_pfx>  <out_crt>"
	exit 1
fi

openssl pkcs12 -in $IN_PFX -out $OUT_CRT -nodes

# if you get problems with PEM private key format, see http://stackoverflow.com/questions/17733536/how-to-convert-a-private-key-to-an-rsa-private-key
# specifically, an ELB wants private keys to begin with
#
#  -----BEGIN RSA PRIVATE KEY-----
#
# although that's actually an old format. the "new" format begins:
#
#  -----BEGIN PRIVATE KEY-----
#
# To convert "new" to "old", so that you can use it with an ELB, try:
#
# openssl rsa -in server.key -out server_rsa.key
