#!/bin/bash

MBED_DIR=/path/to/mbedtls-2.4.2/programs/

echo ${MBED_DIR}
echo ""
echo ""
echo ""

for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $cert
    key=`echo ${cert} | sed -e 's/.pem/.priv.pem/'`
    echo $key
    ${MBED_DIR}/ssl/ssl_server2 crt_file=${cert} key_file=${key} &
    pid=$!
    sleep 1
    ${MBED_DIR}/ssl/ssl_client2 ca_file=certs/ca.pem server_name=127.0.0.1
    kill $pid
    sleep 1
	echo ""
	echo ""
	echo ""
done
