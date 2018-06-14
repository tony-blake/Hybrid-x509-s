import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;

public class GenerateSMIMEApproach1 {

	static String PHONY_ALG_OID = "1.2.3.4.5799";

	public static ASN1Object mungeOIDs(ASN1Object obj) {
		if (obj instanceof ASN1Sequence) {
			ASN1Sequence seq = (ASN1Sequence) obj;
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < seq.size(); i++) {
				ASN1Encodable o = seq.getObjectAt(i);
				if (o instanceof ASN1Sequence || o instanceof ASN1Set) {
					v.add(mungeOIDs((ASN1Object) o));
				} else if (o instanceof ASN1ObjectIdentifier) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) o;
					if (oid.getId().equals("1.2.840.113549.1.1.11")) {
						v.add(new ASN1ObjectIdentifier(PHONY_ALG_OID));
					} else {
						v.add(oid);
					}
				} else if (o instanceof ASN1TaggedObject) {
					ASN1TaggedObject to = (ASN1TaggedObject) o;
					v.add(new DERTaggedObject(to.isExplicit(), to.getTagNo(), mungeOIDs(to.getObject())));
				} else {
					v.add(o);
				}
			}
			return new DLSequence(v);
		} else if (obj instanceof ASN1Set) {
			ASN1Set set = (ASN1Set) obj;
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < set.size(); i++) {
				ASN1Encodable o = set.getObjectAt(i);
				if (o instanceof ASN1Sequence || o instanceof ASN1Set) {
					v.add(mungeOIDs((ASN1Object) o));
				} else if (o instanceof ASN1ObjectIdentifier) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) o;
					if (oid.getId().equals("1.2.840.113549.1.1.11")) {
						v.add(new ASN1ObjectIdentifier(PHONY_ALG_OID));
					} else {
						v.add(oid);
					}
				} else if (o instanceof ASN1TaggedObject) {
					ASN1TaggedObject to = (ASN1TaggedObject) o;
					v.add(new DERTaggedObject(to.isExplicit(), to.getTagNo(), mungeOIDs(to.getObject())));
				} else {
					v.add(o);
				}
			}
			return new DLSet(v);
		} else {
			return obj;
		}
	}

	public static void main(String args[]) throws Exception {

		String path = Config.PATH;
		byte[] derBytes = Files.readAllBytes(Paths.get(path + "/approach0.der"));
		ASN1InputStream a = new ASN1InputStream(derBytes);
		ASN1Primitive ap = a.readObject();
		ASN1Object approach1 = mungeOIDs((ASN1Sequence) ap);
		Files.write(Paths.get(path + "/approach1.der"), approach1.getEncoded());

	}

}
