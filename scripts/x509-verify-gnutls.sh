#!/bin/bash

GNUTLS=/usr/local/bin/gnutls

${GNUTLS}-certtool --version
echo ""
echo ""
echo ""

for i in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $i
    ${GNUTLS}-certtool --infile $i --verify --load-ca-certificate=certs/ca.pem
	echo ""
	echo ""
	echo ""
done
