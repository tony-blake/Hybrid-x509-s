#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

${OPENSSL} version
echo ""
echo ""
echo ""

for i in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $i
	${OPENSSL} verify -verbose -x509_strict -CAfile certs/ca.pem $i
	echo ""
	echo ""
	echo ""
done
