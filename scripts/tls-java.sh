#!/bin/bash

CLASSPATH=java-bin
OPENSSL=/usr/local/opt/openssl/bin/openssl

java -version
echo ""
echo ""
echo ""

rm -f myca.keystore
rm -f myserver.keystore
for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $cert
    key=`echo ${cert} | sed -e 's/.pem/.priv.pem/'`
    echo $key
	${OPENSSL} pkcs12 -inkey $key -in $cert -export -out myserver.p12 -passout pass:passphrase
	keytool -importkeystore -destkeystore myserver.keystore -srckeystore myserver.p12 -alias 1 -deststorepass passphrase -destkeypass passphrase -srcstorepass passphrase
	java -classpath $CLASSPATH SimpleHTTPSServer myserver.keystore passphrase 4444 &
    pid=$!
	sleep 1
	keytool -importcert -noprompt -trustcacerts -alias myca -file certs/ca.pem -keystore myca.keystore -storepass passphrase -keypass passphrase
	java -classpath $CLASSPATH -Djavax.net.ssl.trustStore=myca.keystore -Djavax.net.ssl.trustStorePassword=passphrase SimpleHTTPSClient https://127.0.0.1:4444/
	kill $pid
	sleep 1
	echo ""
	echo ""
	echo ""
	rm -f myca.keystore
	rm -f myserver.keystore
done
