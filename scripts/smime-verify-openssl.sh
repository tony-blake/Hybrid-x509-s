#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

${OPENSSL} version
echo ""
echo ""
echo ""

for i in certs/*/*.smime; do
	echo "==============="
	echo $i
	${OPENSSL} smime -verify -CAfile certs/ca.pem -in $i
	echo ""
	echo ""
	echo ""
done
