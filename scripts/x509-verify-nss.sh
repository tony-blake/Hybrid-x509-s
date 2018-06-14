#!/bin/bash

NSS_DIR=/path/to/nss-3.29.1/dist/Darwin16.5.0_cc_OPT.OBJ
export DYLD_LIBRARY_PATH=${NSS_DIR}/lib

echo $NSS_DIR
echo ""
echo ""
echo ""

rm -f cert8.db key3.db secmod.db
${NSS_DIR}/bin/certutil -A -d . -n myca -t C -i certs/ca.der DYLD_LIBRARY_PATH=${NSS_DIR}/lib

for cert in `find certs/tls -name '*.pem' -and -not -name '*.priv.*'`; do
	echo "==============="
	echo $cert

    nickname=`echo $cert | sed s/certs\\\/tls\\\///g | sed s/.pem//g | sed s/\\\.//g`
    ${NSS_DIR}/bin/certutil -A -d . -n $nickname -t P -i $cert DYLD_LIBRARY_PATH=${NSS_DIR}/lib
    ${NSS_DIR}/bin/certutil -V -d . -n $nickname -u V DYLD_LIBRARY_PATH=${NSS_DIR}/lib
	echo ""
	echo ""
	echo ""
done

${NSS_DIR}/bin/certutil -L -d . DYLD_LIBRARY_PATH=${NSS_DIR}/lib
