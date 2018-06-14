#!/bin/bash

NSS_DIR=/path/to/nss-3.29.1/dist/Darwin16.5.0_cc_OPT.OBJ
export DYLD_LIBRARY_PATH=${NSS_DIR}/lib

echo $NSS_DIR
echo ""
echo ""
echo ""

echo "password" > password.txt
for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
    echo "==============="
	echo $cert
    key=`echo ${cert} | sed -e 's/.pem/.priv.pem/'`
    echo $key
    nickname=`echo $cert | sed s/certs\\\/tls\\\///g | sed s/.pem//g | sed s/\\\.//g`

    rm -f cert8.db key3.db secmod.db
    ${NSS_DIR}/bin/certutil -A -d . -n myca -t C -i certs/ca.der DYLD_LIBRARY_PATH=${NSS_DIR}/lib
    cat $cert $key > combined.txt
    openssl pkcs12 -export -in combined.txt -out combined.pk12 -nodes -passout pass:password -name $nickname
    ${NSS_DIR}/bin/pk12util -v -i combined.pk12 -d . -K password -W password DYLD_LIBRARY_PATH=${NSS_DIR}/lib
    ${NSS_DIR}/bin/selfserv -n $nickname -p 4444 -d . -w password &
    spid=$!
    sleep 1
    ${NSS_DIR}/bin/tstclnt -h 127.0.0.1 -p 4444 -d . -w password -v -C &
    cpid=$!
    sleep 1
    kill $cpid
    kill $spid
    sleep 1
	echo ""
	echo ""
	echo ""
done
