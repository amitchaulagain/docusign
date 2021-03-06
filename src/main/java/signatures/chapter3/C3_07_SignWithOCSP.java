/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.chapter3;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;

public class C3_07_SignWithOCSP extends C3_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/chapter3/hello_cacert_ocsp.pdf";
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {
		Properties properties = new Properties();
		properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
    	String path = properties.getProperty("PRIVATE");
        char[] pass = properties.getProperty("PASSWORD").toCharArray();

		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
		ks.load(new FileInputStream(path), pass);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass);
        Certificate[] chain = ks.getCertificateChain(alias);
        OcspClient ocspClient = new OcspClientBouncyCastle();
        C3_07_SignWithOCSP app = new C3_07_SignWithOCSP();
		app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Test", "Ghent", 
				null, ocspClient, null, 0);
	}
  
}
