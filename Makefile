JARS=java-jars/bcprov-jdk15on-156.jar:java-jars/bcpkix-jdk15on-156.jar:java-jars/bcmail-jdk15on-156.jar:java-jars/javax.mail.jar

phony:

build:
	mkdir -p java-bin
	javac -d java-bin -classpath ${JARS} java-src/Config.java java-src/GenerateCerts.java java-src/GenerateSMIME.java
	javac -d java-bin java-src/SimpleHTTPSClient.java java-src/SimpleHTTPSServer.java

generate:
	java -classpath ${JARS}:java-bin GenerateCerts

clean:
	rm -rf certs
	rm -rf java-bin
	rm -f myserver.p12
	rm -f .DS_Store
