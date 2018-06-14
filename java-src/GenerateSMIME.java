import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.mail.BodyPart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javafx.util.Pair;

public class GenerateSMIME {

	static SignerInfo makeSignerInfo(String msg, X509Certificate signerCert, KeyPair signerKP) throws Exception {
		CMSSignedData signedData = makeSignedData(msg, signerCert, signerKP, null);
		SignerInformationStore signerInfoStore = signedData.getSignerInfos();
		if (signerInfoStore.size() != 1) {
			throw new Exception("Unexpected signerInfoStore size");
		}
		for (SignerInformation signerInfo : signerInfoStore.getSigners()) {
			return signerInfo.toASN1Structure();
		}
		return null;
	}

	static CMSSignedData makeSignedData(String msg, X509Certificate signerCert, KeyPair signerKP, CMSAttributeTableGenerator signedAttributeGenerator) throws Exception {

		JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC");
		if (signedAttributeGenerator != null) {
			builder = builder.setSignedAttributeGenerator(signedAttributeGenerator);
		}
		SignerInfoGenerator signerInfoGen = builder.build("SHA256withRSA", signerKP.getPrivate(), signerCert);

		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(signerCert);
		JcaCertStore certs = new JcaCertStore(certList);

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		gen.addSignerInfoGenerator(signerInfoGen);
		gen.addCertificates(certs);
		return gen.generate(new CMSProcessableByteArray(msg.getBytes()), false);

	}

	static MimeMessage makeSMIMESignedMessage(String from, String msg, List<X509Certificate> extraCerts, X509Certificate signerCert, KeyPair signerKP, CMSAttributeTableGenerator signedAttributeGenerator, String basename) throws Exception {

		JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC");
		if (signedAttributeGenerator != null) {
			builder = builder.setSignedAttributeGenerator(signedAttributeGenerator);
		}
		SignerInfoGenerator signerInfoGen = builder.build("SHA256withRSA", signerKP.getPrivate(), signerCert);

		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		if (extraCerts != null) {
			certList.addAll(extraCerts);
		}
		certList.add(signerCert);
		JcaCertStore certs = new JcaCertStore(certList);

		SMIMESignedGenerator gen = new SMIMESignedGenerator();
		gen.addSignerInfoGenerator(signerInfoGen);
		gen.addCertificates(certs);

		MimeBodyPart mimeBodyPart = new MimeBodyPart();
		mimeBodyPart.setText(msg);
		MimeMultipart multipart = gen.generate(mimeBodyPart);
		return makeMimeMessage(from, multipart, basename);
	}

	static MimeMessage makeMimeMessage(String from, MimeMultipart multipart, String basename) throws Exception {
		Properties properties = System.getProperties();
		Session session = Session.getDefaultInstance(properties);
		MimeMessage mimeMsg = new MimeMessage(session);
		mimeMsg.addHeader("From", from);
		mimeMsg.setContent(multipart);
		if (basename != null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			mimeMsg.writeTo(baos);
			Files.write(Paths.get(basename + ".smime"), baos.toByteArray());
		}
		return mimeMsg;
	}

	static String PHONY_ATTRIBUTE_ID = "1.2.3.4.5839";

	static MimeMessage approach0(String from, String msg, X509Certificate cert1, KeyPair kp1, X509Certificate cert2, KeyPair kp2, String basename) throws Exception {

		SMIMESignedGenerator gen = new SMIMESignedGenerator();
		List<X509Certificate> certList = new ArrayList<X509Certificate>();

		JcaSimpleSignerInfoGeneratorBuilder builder1 = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC");
		SignerInfoGenerator signerInfoGen1 = builder1.build("SHA1withRSA", kp1.getPrivate(), cert1);
		certList.add(cert1);
		gen.addSignerInfoGenerator(signerInfoGen1);

		JcaSimpleSignerInfoGeneratorBuilder builder2 = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC");
		SignerInfoGenerator signerInfoGen2 = builder2.build("SHA256withRSA", kp2.getPrivate(), cert2);
		certList.add(cert2);
		gen.addSignerInfoGenerator(signerInfoGen2);

		gen.addCertificates(new JcaCertStore(certList));

		MimeBodyPart mimeBodyPart = new MimeBodyPart();
		mimeBodyPart.setText(msg);
		MimeMultipart multipart = gen.generate(mimeBodyPart);

		return makeMimeMessage(from, multipart, basename);

	}

	static MimeMessage approach2a(String from, String msg, X509Certificate innerCert, KeyPair innerKP, X509Certificate outerCert, KeyPair outerKP, String basename) throws Exception {
		SignerInfo signerInfo = makeSignerInfo(msg, innerCert, innerKP);
		Attribute myExtraAttribute = new Attribute(new ASN1ObjectIdentifier(PHONY_ATTRIBUTE_ID), new DERSet(signerInfo));
		AttributeTable myExtraAttributes = new AttributeTable(myExtraAttribute);
		DefaultSignedAttributeTableGenerator attributeGenerator = new DefaultSignedAttributeTableGenerator(myExtraAttributes);
		List<X509Certificate> extraCerts = new ArrayList<X509Certificate>();
		extraCerts.add(innerCert);
		return makeSMIMESignedMessage(from, msg, extraCerts, outerCert, outerKP, attributeGenerator, basename);
	}

	static MimeMessage approach2b(String from, String msg, X509Certificate hybridCert, KeyPair subjKP, String basename) throws Exception {
		SignerInfo signerInfo = makeSignerInfo(msg, hybridCert, subjKP);
		Attribute myExtraAttribute = new Attribute(new ASN1ObjectIdentifier(PHONY_ATTRIBUTE_ID), new DERSet(signerInfo));
		AttributeTable myExtraAttributes = new AttributeTable(myExtraAttribute);
		DefaultSignedAttributeTableGenerator attributeGenerator = new DefaultSignedAttributeTableGenerator(myExtraAttributes);
		return makeSMIMESignedMessage(from, msg, null, hybridCert, subjKP, attributeGenerator, basename);
	}

	static MimeMessage approach2c(String from, String msg, X509Certificate innerCert, KeyPair innerKP, X509Certificate outerCert, KeyPair outerKP, String basename) throws Exception {
		CMSSignedData signedData = makeSignedData(msg, innerCert, innerKP, null);
		Attribute myExtraAttribute = new Attribute(new ASN1ObjectIdentifier(PHONY_ATTRIBUTE_ID), new DERSet(signedData.toASN1Structure()));
		AttributeTable myExtraAttributes = new AttributeTable(myExtraAttribute);
		DefaultSignedAttributeTableGenerator attributeGenerator = new DefaultSignedAttributeTableGenerator(myExtraAttributes);
		return makeSMIMESignedMessage(from, msg, null, outerCert, outerKP, attributeGenerator, basename);
	}

	public static void main(String from, String path, Hashtable<String, Pair<KeyPair, X509Certificate>> certs, X509Certificate caCert) throws Exception {

		String msg = "This is a test message.";

		X509Certificate innerCert = certs.get("rsaA").getValue();
		KeyPair innerKP = certs.get("rsaA").getKey();
		X509Certificate outerCert = certs.get("rsaB").getValue();
		KeyPair outerKP = certs.get("rsaB").getKey();

		SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(outerCert);
		SMIMEToolkit smimeToolkit = new SMIMEToolkit(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());

		MimeMessage mimeMsg = makeSMIMESignedMessage(from, msg, null, outerCert, outerKP, null, path + "single-rsaA");
		System.out.println("Created basic SMIME signed message.");
		System.out.println("  Is signed?          " + smimeToolkit.isSigned(mimeMsg));
		System.out.println("  Is valid signature? " + smimeToolkit.isValidSignature(mimeMsg, verifier));

		MimeMessage mimeMsg1 = approach0(from, msg, innerCert, innerKP, outerCert, outerKP, path + "hybrid-approach0-rsaA-rsaB");
		System.out.println("Created hybrid SMIME signed message using approach 0.");
		System.out.println("  Is signed?          " + smimeToolkit.isSigned(mimeMsg1));
		System.out.println("  Is valid signature? " + smimeToolkit.isValidSignature(mimeMsg1, verifier));

		MimeMessage mimeMsg2a = approach2a(from, msg, innerCert, innerKP, outerCert, outerKP, path + "hybrid-approach2a-rsaA-rsaBouter");
		System.out.println("Created hybrid SMIME signed message using approach 2(a).");
		System.out.println("  Is signed?          " + smimeToolkit.isSigned(mimeMsg2a));
		System.out.println("  Is valid signature? " + smimeToolkit.isValidSignature(mimeMsg2a, verifier));

		for (Enumeration<String> hybridSizes = certs.keys(); hybridSizes.hasMoreElements();) {
			String hybridSize = hybridSizes.nextElement();
			if (!hybridSize.endsWith("K")) continue;
			Pair<KeyPair, X509Certificate> values = certs.get(hybridSize);
			MimeMessage mimeMsg2b = approach2b(from, msg + " Has a " + hybridSize + " hybrid certificate.", values.getValue(), values.getKey(), path + "hybrid-approach2b-" + hybridSize);
			System.out.println("Created hybrid SMIME signed message using approach 2(b) with hybrid certificate " + hybridSize + ".");
			System.out.println("  Is signed?          " + smimeToolkit.isSigned(mimeMsg2b));
			verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(values.getValue());
			System.out.println("  Is valid signature? " + smimeToolkit.isValidSignature(mimeMsg2b, verifier));
		}

		verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(outerCert);
		MimeMessage mimeMsg2c = approach2c(from, msg, innerCert, innerKP, outerCert, outerKP, path + "hybrid-approach2c-rsaA-rsaBouter");
		System.out.println("Created hybrid SMIME signed message using approach 2(c).");
		System.out.println("  Is signed?          " + smimeToolkit.isSigned(mimeMsg2c));
		System.out.println("  Is valid signature? " + smimeToolkit.isValidSignature(mimeMsg2c, verifier));

	}


}
