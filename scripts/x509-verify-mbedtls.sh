#!/bin/bash

MBED_DIR=/path/to/mbedtls-2.4.2/programs/

echo ${MBED_DIR}
echo ""
echo ""
echo ""

for i in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $i
    ${MBED_DIR}/x509/cert_app mode=file filename=$i ca_file=certs/ca.pem
	echo ""
	echo ""
	echo ""
done
