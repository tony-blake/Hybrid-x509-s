# Tests for paper "Transitioning to a quantum-resistant public key infrastructure"

This directory contains scripts for reproducing experimental results from the following paper:

- Nina Bindel, Udyani Herath, Matthew McKague, Douglas Stebila. **Transitioning to a quantum-resistant public key infrastructure**.  In *Proc. PQCrypto 2017*, *LNCS*, Springer.  To appear.

This code was originally distributed from [https://www.douglas.stebila.ca/code/pq-pki-tests/](https://www.douglas.stebila.ca/code/pq-pki-tests/).

## Building

1. Download `bcprov-jdk15on-156.jar`, `bcpkix-jdk15on-156.jar`, and `bcmail-jdk15on-156.jar` from [https://bouncycastle.org/latest_releases.html](https://bouncycastle.org/latest_releases.html) and place in folder `java-jars`.  (You can use a more recent version, but will need to edit the `Makefile`.)
2. Download `javax.mail.jar` from [https://javaee.github.io/javamail/](https://javaee.github.io/javamail/) and place in folder `java-jars`
3. Edit `java-src/Config.java` to configure paths.
4. Run `make build`

## Generating certificates

1. Follow the build instructions above.
2. Run `make generate`

## Running X.509 tests

- GnuTLS:
	- Download GnuTLS from [https://gnutls.org/download.html](https://gnutls.org/download.html) and build it, or install using your package manager.  On OS X, `brew install gnutls`
	- Edit `scripts/x509-verify-gnutls.sh` to change variable `GNUTLS`
	- Run `scripts/x509-verify-gnutls.sh`
- Java:
	- These tests are run during `make generate` above.
- mbedTLS:
	- Download mbedTLS from [https://tls.mbed.org/](https://tls.mbed.org/) and build it.  (Tested on version 2.42.)
	- Edit `scripts/x509-verify-mbedtls.sh` to change variable `MBED_DIR`
	- Run `scripts/x509-verify-mbedtls.sh`
- NSS:
	- Download NSS from [https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) and build it.  (Tested on version 3.29.1.)
	- Edit `scripts/x509-verify-nss.sh` to change variable `NSS_DIR`
	- Run `scripts/x509-verify-nss.sh`
- OpenSSL:
	- Download OpenSSL from [https://www.openssl.org/](https://www.openssl.org/) and build it, or install using your package manager.  On OS X, `brew install openssl` to get a recent version (OS X's default install is old.)
	- Edit `scripts/x509-verify-openssl.sh` to change variable `OPENSSL`
	- Run `scripts/x509-verify-openssl.sh`

## Running S/MIME tests

- Java:
	- These tests are run during `make generate` above.
- OpenSSL:
	- Edit `scripts/smime-verify-openssl.sh` to change variable `OPENSSL`
	- Run `scripts/smime-verify-openssl.sh`
- Other programs:
	- You will need to take the `.smime` messages in `certs/smime` and import them into the mail program in question, possibly by mailing the contents to yourself so it shows up as a received message.

Running S/MIME tests for Approach 1 requires manually extracting the PEM data from an S/MIME message (e.g., `hybrid-approach0-rsaA-rsaB.smime`), converting that to DER format, running the Java program `GenerateSMIMEApproach1`, which outputs new DER data, converting that back to PEM, and then inserting it back into a full S/MIME message.

## Running TLS tests

- GnuTLS, mbedTLS, NSS, OpenSSL:
	- Edit `scripts/tls-XXX.sh` to change appropriate variable to point to executable if needed.
	- Run `scripts/tls-XXX.sh`
- Java:
	- Edit `scripts/tls-java.sh` to change appropriate variable to point to OpenSSL executable if needed.
	- Run `scripts/tls-java.sh`
