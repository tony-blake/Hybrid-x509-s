#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

${OPENSSL} version
echo ""
echo ""
echo ""

for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $cert
    key=`echo ${cert} | sed -e 's/.pem/.priv.pem/'`
    echo $key
    ${OPENSSL} s_server -cert $cert -key $key -www &
    pid=$!
    echo "GET /" | ${OPENSSL} s_client -CAfile certs/ca.pem
    kill $pid
	echo ""
	echo ""
	echo ""
done
