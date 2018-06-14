import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.*;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class SimpleHTTPSClient {

	public static void main(String[] args) throws Exception {
		
		if (args.length != 1) {
			System.err.println("Usage: SimpleHTTPSClient url");
			return;
		}
	
		String httpsURL = args[0];
		URL myurl = new URL(httpsURL);
		HttpsURLConnection con = (HttpsURLConnection) myurl.openConnection();

		InputStream ins = con.getInputStream();
		InputStreamReader isr = new InputStreamReader(ins);
		BufferedReader in = new BufferedReader(isr);

		Certificate[] certs = con.getServerCertificates();
		for (Certificate cert : certs) {
			System.out.println(cert.toString());
		}
		System.out.println();
		System.out.println();
		System.out.println();

		String inputLine;
		while ((inputLine = in.readLine()) != null) {
			System.out.println(inputLine);
		}

		in.close();
		
	}

}
