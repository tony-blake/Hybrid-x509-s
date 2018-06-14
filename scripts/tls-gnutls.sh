#!/bin/bash

killall gnutls-serv &> /dev/null
killall gnutls-cli &> /dev/null

GNUTLS=/usr/local/bin/gnutls

${GNUTLS}-cli --version
echo ""
echo ""
echo ""

for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $cert
    key=`echo ${cert} | sed -e 's/.pem/.priv.pem/'`
    echo $key
    ${GNUTLS}-serv --x509cafile certs/ca.pem --x509certfile $cert --x509keyfile $key &
    spid=$!
    sleep 1
    ${GNUTLS}-cli -p 5556 --x509cafile certs/ca.pem 127.0.0.1 &
    cpid=$!
    sleep 1
    kill $spid &> /dev/null
    kill $cpid &> /dev/null
	echo ""
	echo ""
	echo ""
done
