
IN_CRT=$1
OUT_PEM=$2

if [ -z "$OUT_PEM" ]; then
	echo "Usage:  crt2pem.sh  <in_crt>  <out_pem>"
	exit 1
fi

openssl x509 -inform der -in $IN_CRT -out $OUT_PEM

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
