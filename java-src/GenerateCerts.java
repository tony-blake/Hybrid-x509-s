import java.io.*;
import java.math.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javafx.util.Pair;
import sun.security.provider.certpath.SunCertPathBuilderException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.openssl.PEMWriter;

public class GenerateCerts {

	static int serialNumber = 1;

	static void saveCertificate(KeyPair kp, X509Certificate cert, String basename) throws Exception {
		if (basename != null) {
			// save DER certificate
			Files.write(Paths.get(basename + ".der"), cert.getEncoded());
			// save PEM certificate
			CharArrayWriter charWriter = new CharArrayWriter();
			PEMWriter pemWriter = new PEMWriter(charWriter);
			pemWriter.writeObject(cert);
			pemWriter.close();
			Files.write(Paths.get(basename + ".pem"), charWriter.toString().getBytes());
			// save DER private key
			Files.write(Paths.get(basename + ".priv.der"), kp.getPrivate().getEncoded());
			// save PEM private key
			charWriter = new CharArrayWriter();
			pemWriter = new PEMWriter(charWriter);
			pemWriter.writeObject(kp.getPrivate());
			pemWriter.close();
			Files.write(Paths.get(basename + ".priv.pem"), charWriter.toString().getBytes());
		}
	}

	static X509Certificate makeCertificate(KeyPair subKP, String subDN, KeyPair issKP, String issDN, String basename)
			throws Exception {
		PublicKey subPub = subKP.getPublic();
		PrivateKey issPriv = issKP.getPrivate();
		PublicKey issPub = issKP.getPublic();

		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(new X500Name(issDN),
				BigInteger.valueOf(serialNumber++), new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(subDN), subPub);

		v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils()
				.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));
		v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
				new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
		v3CertGen.addExtension(X509Extension.subjectAlternativeName, false,
				new GeneralNames(new GeneralName(GeneralName.iPAddress, Config.DOMAIN)));
		if (issDN.equals(subDN)) {
			v3CertGen.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());
		}

		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
				v3CertGen.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issPriv)));
		saveCertificate(subKP, cert, basename);
		return cert;
	}

	static String PHONY_HYBRID_CERT_OID = "1.2.3.4.5784";

	static X509Certificate makeHybridCertificate(KeyPair subKP, String subDN, KeyPair issKP, String issDN, int extSize, String basename)
			throws Exception {
		PublicKey subPub = subKP.getPublic();
		PrivateKey issPriv = issKP.getPrivate();
		PublicKey issPub = issKP.getPublic();

		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(new X500Name(issDN),
				BigInteger.valueOf(serialNumber++), new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(subDN), subPub);

		v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils()
				.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));
		v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
				new AuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
		v3CertGen.addExtension(X509Extension.subjectAlternativeName, false,
				new GeneralNames(new GeneralName(GeneralName.iPAddress, Config.DOMAIN)));
		if (issDN.equals(subDN)) {
			v3CertGen.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());
		}

		byte[] extBytes = new byte[extSize];
		for (int i = 0; i < extSize; i++) {
			extBytes[i] = (byte) i;
		}
		v3CertGen.addExtension(new ASN1ObjectIdentifier(PHONY_HYBRID_CERT_OID), false, extBytes);

		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
				v3CertGen.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issPriv)));
		saveCertificate(subKP, cert, basename);
		return cert;
	}

	static String PHONY_ALG_OID = "1.2.3.4.5785";

	public static DLSequence mungeOIDs(ASN1Sequence seq) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (int i = 0; i < seq.size(); i++) {
			ASN1Encodable o = seq.getObjectAt(i);
			if (o instanceof ASN1Sequence) {
				v.add(mungeOIDs((ASN1Sequence) o));
			} else if (o instanceof ASN1ObjectIdentifier) {
				v.add(new ASN1ObjectIdentifier(PHONY_ALG_OID));
			} else {
				v.add(o);
			}
		}
		return new DLSequence(v);
	}

	public static ASN1Object mungeObjectOIDs(X509Certificate cert) throws Exception {
		byte[] b = cert.getEncoded();
		ASN1InputStream a = new ASN1InputStream(b);
		ASN1Primitive ap = a.readObject();
		return mungeOIDs((ASN1Sequence) ap);
	}

	public static Hashtable<String, Pair<KeyPair, X509Certificate>> makeCerts(String cn, KeyPairGenerator kpg, KeyPair caKP, X509Certificate caCert, String caDN, String basename) throws Exception {

		Hashtable<String, Pair<KeyPair, X509Certificate>> outputs = new Hashtable<String, Pair<KeyPair, X509Certificate>>();

		String rsaADN = "CN=" + cn + ", O=Basic certificate A with 2048-bit RSA key, C=CA";
		KeyPair rsaAKP = kpg.generateKeyPair();
		X509Certificate rsaACert = makeCertificate(rsaAKP, rsaADN, caKP, caDN, basename + "/rsa2048a");
		outputs.put("rsaA", new Pair<KeyPair, X509Certificate>(rsaAKP, rsaACert));
		System.out.println("Created basic certificate A with 2048-bit RSA key.");
		System.out.println("  Is valid? " + validateCertificate(rsaACert, caCert));

		String rsaBDN = "CN=" + cn + ", O=Basic certificate B with 2048-bit RSA key, C=CA";
		KeyPair rsaBKP = kpg.generateKeyPair();
		X509Certificate rsaBCert = makeCertificate(rsaBKP, rsaBDN, caKP, caDN, basename + "/rsa2048b");
		outputs.put("rsaB", new Pair<KeyPair, X509Certificate>(rsaBKP, rsaBCert));
		System.out.println("Created basic certificate B with 2048-bit RSA key.");
		System.out.println("  Is valid? " + validateCertificate(rsaBCert, caCert));

		double[] hybridSizes = {1.5, 3.5, 9.0, 43.0, 1333.0};
		for (double hybridSize : hybridSizes) {
			String dn = String.format("CN=" + cn + ", O=Hybrid certificate with %03.1fKB extension, C=CA", hybridSize);
			KeyPair kp = kpg.generateKeyPair();
			X509Certificate cert = makeHybridCertificate(kp, dn, caKP, caDN, (int) (1024 * hybridSize), basename + String.format("/hyb%03.1fK", hybridSize));
			outputs.put(String.format("%03.1fK", hybridSize), new Pair<KeyPair, X509Certificate>(kp, cert));
			System.out.println(String.format("Created hybrid certificate with %03.1fKB extension.", hybridSize));
			System.out.println("  Is valid? " + validateCertificate(cert, caCert));
		}

		String unknownDN = "CN=" + cn + ", O=Certificate with 2048-bit unknown key, C=CA";
		KeyPair unknownKP = kpg.generateKeyPair();
		X509Certificate unmungedCert = makeCertificate(unknownKP, unknownDN, caKP, caDN, null);
		ASN1Object unknownCert = mungeObjectOIDs(unmungedCert);
		Files.write(Paths.get(basename + "/unknown.der"), unknownCert.getEncoded());
		System.out.println("Created certificate with unknown key.");
		// System.out.println("  Is valid? " + validateCertificate(unknownCert, caCert));

		return outputs;

	}

	public static boolean validateCertificate(X509Certificate cert, X509Certificate caCert) {
		try {
			HashSet<TrustAnchor> anchors = new HashSet<TrustAnchor>();
			anchors.add(new TrustAnchor(caCert, null));

			X509CertSelector target = new X509CertSelector();
			target.setCertificate(cert);

			PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
			params.setRevocationEnabled(false);

			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
			CertPathBuilderResult r = builder.build(params);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(((SunCertPathBuilderException) e).getAdjacencyList());
			return false;
		}
		return true;
	}

	public static void main(String[] args) throws Exception {

		String path = Config.PATH;
		String email = Config.EMAIL;

		Files.createDirectories(Paths.get(path));
		Files.createDirectories(Paths.get(path + "/smime"));
		Files.createDirectories(Paths.get(path + "/tls"));

		System.out.println("Running...");

		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(2048, new SecureRandom());

		String caDN = "O=My CA with 2048-bit RSA key, C=CA";
		KeyPair caKP = kpg.generateKeyPair();
		X509Certificate caCert = makeCertificate(caKP, caDN, caKP, caDN, path + "/ca");
		System.out.println("Created CA certificate.");
		System.out.println("  Is valid? " + validateCertificate(caCert, caCert));

		Hashtable<String, Pair<KeyPair, X509Certificate>> tlsCerts = makeCerts(Config.DOMAIN, kpg, caKP, caCert, caDN, path + "/tls/");
		Hashtable<String, Pair<KeyPair, X509Certificate>> smimeCerts = makeCerts(email, kpg, caKP, caCert, caDN, path + "/smime/");

		GenerateSMIME.main(email, path + "/smime/", smimeCerts, caCert);

		System.out.println("Done.");

	}

}
