#!/bin/bash

PATH=/usr/local/ssl/bin:$PATH

# Get CA cert
rm 443-root.crt
wget http://test-pqpki.com/443-root.crt

export EST_OPENSSL_CACERT=`realpath 443-root.crt`

pushd example/client

export OUTPUT_DIR=/tmp/EST
export OUTPUT_PKCS7_CACERT=$OUTPUT_DIR/cacert-0-0.pkcs7
export OUTPUT_PEM_CACERT=$OUTPUT_DIR/cacert-0-0.pem
export OUTPUT_PKCS7_CERT=$OUTPUT_DIR/cert-0-0.pkcs7
export OUTPUT_PEM_CERT=$OUTPUT_DIR/cert-0-0.pem

export EST_HOST=test-pqpki.com
export EST_PORT=443
# Try it with IPv4 or IPv6 addresses if you like:
#export EST_HOST=18.217.192.8
#export EST_HOST=2600:1f16:61c:2f02:aa2c:84ac:3758:922e

export VERBOSE_FLAG=

rm -rf $OUTPUT_DIR
mkdir -p $OUTPUT_DIR

function print_and_verify_cert()
{
	CERT=$1
	CA_CERT=$2

	# Print new cert
	openssl x509 -engine qs_sig -in $CERT -noout -text

	# Verify the cert's classical signature
	openssl verify -CAfile $CA_CERT $CERT || exit 1
	echo "Classical verification success"

	# Verify the cert's alt signature
	openssl x509QSVerify -engine qs_sig -root $CA_CERT -untrusted $CERT  -cert $CERT || exit 1
	echo "Alt Signature verification success"
}

# Fetch CA cert
./estclient $VERBOSE_FLAG -g -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -o $OUTPUT_DIR || exit 1
echo "Fetch CA cert success"

########################################
# estclient tests
########################################

# print CA cert
openssl base64 -d -in $OUTPUT_PKCS7_CACERT | openssl pkcs7 -engine qs_sig -inform DER -text -print_certs -noout

# Convert PKCS7 CA Cert to PEM
openssl base64 -d -in $OUTPUT_PKCS7_CACERT | openssl pkcs7 -inform DER  -print_certs -out $OUTPUT_PEM_CACERT || exit 1

# Enroll a new cert with new key
./estclient $VERBOSE_FLAG -e  --common-name "Newly Enrolled MPKAC" -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -o $OUTPUT_DIR --pem-output || exit 1
date
sleep 13
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment success"

# Copy aside the private keys
cp $OUTPUT_DIR/key-x-x.pem $OUTPUT_DIR/savekey.pem
cp $OUTPUT_DIR/alt-key-x-x.pem $OUTPUT_DIR/alt-savekey.pem
cp $OUTPUT_PEM_CERT $OUTPUT_DIR/savecert.pem

# Re-enrol the cert
#./estclient $VERBOSE_FLAG -r -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -c $OUTPUT_DIR/savecert.pem -k $OUTPUT_DIR/savekey.pem --k-alt $OUTPUT_DIR/alt-savekey.pem -o $OUTPUT_DIR --pem-output || exit 1
#print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
#echo "Cert re-enrollment success"

# Enroll a new cert using the previous cert and keys for client auth and the previous cert signing keys.
./estclient $VERBOSE_FLAG -e  --common-name "Newly Enrolled MPKAC 2" -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -c $OUTPUT_DIR/savecert.pem -k $OUTPUT_DIR/savekey.pem --k-alt $OUTPUT_DIR/alt-savekey.pem -x $OUTPUT_DIR/savekey.pem --x-alt $OUTPUT_DIR/alt-savekey.pem -o $OUTPUT_DIR --pem-output || exit 1
date
sleep 13
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment with client auth success"

# Generate keys and CSR using openssl
openssl genpkey -engine qs_sig -algorithm hss -pkeyopt winternitz_value:8 -pkeyopt tree_height:5 -out $OUTPUT_DIR/openssl_hss_key.pem || exit 1
openssl ecparam -out $OUTPUT_DIR/ecdsa_mpkac_parameters.pem -name secp521r1 || exit 1
openssl req         -new -newkey ec:$OUTPUT_DIR/ecdsa_mpkac_parameters.pem -keyout $OUTPUT_DIR/openssl_ecdsa_key.pem -out $OUTPUT_DIR/openssl_ecdsa_req.pem -config isara_req.cfg -nodes || exit 1
openssl reqQSExtend -engine qs_sig -reqin $OUTPUT_DIR/openssl_ecdsa_req.pem -reqout $OUTPUT_DIR/openssl_mpkac_req.pem -privin $OUTPUT_DIR/openssl_ecdsa_key.pem -privqs $OUTPUT_DIR/openssl_hss_key.pem || exit 1

# Enroll a new cert with keys from openssl
./estclient $VERBOSE_FLAG -e  --common-name "Newly Enrolled MPKAC from openssl keys" -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -x $OUTPUT_DIR/openssl_ecdsa_key.pem --x-alt $OUTPUT_DIR/openssl_hss_key.pem -o $OUTPUT_DIR --pem-output || exit 1
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment with openssl keys success"

# Enroll a new cert with pure ECDSA CSR from openssl. The cert won't contain
# a Subject Alt Public Key Info, but it will contain an Alt Signature from the
# CA. MPKA cert and keys are used for client auth.
./estclient $VERBOSE_FLAG -e -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -y $OUTPUT_DIR/openssl_ecdsa_req.pem -c $OUTPUT_DIR/savecert.pem -k $OUTPUT_DIR/savekey.pem --k-alt $OUTPUT_DIR/alt-savekey.pem -o $OUTPUT_DIR --pem-output || exit 1
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment with openssl ECDSA CSR success"

# Copy aside non-MPKA cert
cp $OUTPUT_PEM_CERT $OUTPUT_DIR/ecdsa_savecert.pem

# Re-enrol the non-MPKA cert using non-MPKA cert for client auth
./estclient $VERBOSE_FLAG -r -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -c $OUTPUT_DIR/ecdsa_savecert.pem -k $OUTPUT_DIR/openssl_ecdsa_key.pem -o $OUTPUT_DIR --pem-output || exit 1
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "Cert re-enrollment success"

# Enroll a new MPKA cert using the previous ECDSA cert and key for client auth and the previous ECDSA signing keys, HSS key will be generated.
./estclient $VERBOSE_FLAG -e  --common-name "Newly Enrolled MPKAC 3" -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -c $OUTPUT_DIR/ecdsa_savecert.pem -k $OUTPUT_DIR/openssl_ecdsa_key.pem -x $OUTPUT_DIR/openssl_ecdsa_key.pem -o $OUTPUT_DIR --pem-output || exit 1
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment from ECDSA cert with client auth success"

# Enroll a new cert with MPKA CSR from openssl.  MPKA cert and keys are used
# for client auth.
./estclient $VERBOSE_FLAG -e -u estuser -h estpwd -s $EST_HOST -p $EST_PORT -y $OUTPUT_DIR/openssl_mpkac_req.pem -c $OUTPUT_DIR/savecert.pem -k $OUTPUT_DIR/savekey.pem --k-alt $OUTPUT_DIR/alt-savekey.pem -o $OUTPUT_DIR --pem-output || exit 1
print_and_verify_cert $OUTPUT_PEM_CERT $OUTPUT_PEM_CACERT
echo "New cert enrollment with openssl MPKA CSR success"


########################################
# estclient-simple tests
########################################

popd
pushd example/client-simple

# Enroll new cert using estclient-simple
./estclient_simple -u estuser -h estpwd -s $EST_HOST -p $EST_PORT || exit 1
# convert estclient-simple cert to PEM
openssl base64 -d -in cert-b64.pkcs7 | openssl pkcs7 -inform DER  -print_certs -out $OUTPUT_DIR/estclient-simple.pem || exit 1
print_and_verify_cert $OUTPUT_DIR/estclient-simple.pem $OUTPUT_PEM_CACERT
echo "New estclient_simple cert enrollment success"

echo
echo "--------------------"
echo "Success!!"
echo "--------------------"
echo