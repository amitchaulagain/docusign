/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.booleant;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class C2_11_SignatureWorkflow {
	public static final String FORM = "src/main/resources/hello.pdf";
	public static final String ALICE = "src/main/resources/hero.cert";
	public static final String BOB = "src/main/resources/bob";
	public static final String CAROL = "src/main/resources/carol";
	public static final String DAVE = "src/main/resources/dave";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String DEST = "src/main/resources/results/step%s_signed_by_%s.pdf";

	public class MyTextFieldEvent implements PdfPCellEvent {

		public String name;

		public MyTextFieldEvent(String name) {
			this.name = name;
		}

		public void cellLayout(PdfPCell cell, Rectangle position,
							   PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			TextField text = new TextField(writer, position, name);
			try {
				writer.addAnnotation(text.getTextField());
			} catch (IOException e) {
				throw new ExceptionConverter(e);
			} catch (DocumentException e) {
				throw new ExceptionConverter(e);
			}
		}
	}

	public class MySignatureFieldEvent implements PdfPCellEvent {

		public PdfFormField field;

		public MySignatureFieldEvent(PdfFormField field) {
			this.field = field;
		}

		public void cellLayout(PdfPCell cell, Rectangle position,
							   PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			field.setPage();
			field.setWidget(position, PdfAnnotation.HIGHLIGHT_INVERT);
			writer.addAnnotation(field);
		}

	}

	public void createForm() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(FORM));
		document.open();
		PdfPTable table = new PdfPTable(1);
		table.setWidthPercentage(100);
		table.addCell("Written by Alice");
		table.addCell(createSignatureFieldCell(writer, "sig1"));
		table.addCell("For approval by Bob");
		table.addCell(createTextFieldCell("approved_bob"));
		table.addCell(createSignatureFieldCell(writer, "sig2"));
		table.addCell("For approval by Carol");
		table.addCell(createTextFieldCell("approved_carol"));
		table.addCell(createSignatureFieldCell(writer, "sig3"));
		table.addCell("For approval by Dave");
		table.addCell(createTextFieldCell("approved_dave"));
		table.addCell(createSignatureFieldCell(writer, "sig4"));
		document.add(table);
		document.close();
	}

	protected PdfPCell createTextFieldCell(String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(20);
		cell.setCellEvent(new MyTextFieldEvent(name));
		return cell;
	}

	protected PdfPCell createSignatureFieldCell(PdfWriter writer, String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(50);
		PdfFormField field = PdfFormField.createSignature(writer);
		field.setFieldName(name);
		field.setFlags(PdfAnnotation.FLAGS_PRINT);
		cell.setCellEvent(new MySignatureFieldEvent(field));
		return cell;
	}

	public void certify(String keystore,
						String src, String name, String dest)
			throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
		String alias = (String)ks.aliases().nextElement();
		PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
		Certificate[] chain = ks.getCertificateChain(alias);
		// Creating the reader and the stamper
		PdfReader reader = new PdfReader(src);
		FileOutputStream os = new FileOutputStream(dest);
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		// Creating the appearance
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature(name);
		appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
		// Creating the signature
		ExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
		ExternalDigest digest = new BouncyCastleDigest();
		MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}

	public void fillOut(String src, String dest, String name, String value) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
		AcroFields form = stamper.getAcroFields();
		form.setField(name, value);
		form.setFieldProperty(name, "setfflags", PdfFormField.FF_READ_ONLY, null);
		stamper.close();
	}

	public void sign(String keystore,
					 String src, String name, String dest)
			throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
		String alias = (String)ks.aliases().nextElement();
		PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
		Certificate[] chain = ks.getCertificateChain(alias);
		// Creating the reader and the stamper
		PdfReader reader = new PdfReader(src);
		FileOutputStream os = new FileOutputStream(dest);
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		// Creating the appearance
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature(name);
		// Creating the signature
		ExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
		ExternalDigest digest = new BouncyCastleDigest();
		MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}

	public void fillOutAndSign(String keystore,
							   String src, String name, String fname, String value, String dest)
			throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
		String alias = (String)ks.aliases().nextElement();
		PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
		Certificate[] chain = ks.getCertificateChain(alias);
		// Creating the reader and the stamper
		PdfReader reader = new PdfReader(src);
		FileOutputStream os = new FileOutputStream(dest);
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		AcroFields form = stamper.getAcroFields();
		form.setField(fname, value);
		form.setFieldProperty(fname, "setfflags", PdfFormField.FF_READ_ONLY, null);
		// Creating the appearance
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature(name);
		// Creating the signature
		ExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
		ExternalDigest digest = new BouncyCastleDigest();
		MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}

	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C2_11_SignatureWorkflow app = new C2_11_SignatureWorkflow();
		//app.createForm();
		app.certify(ALICE, FORM, "sig1", String.format(DEST, 1, "alice"));
		app.fillOut(String.format(DEST, 1, "alice"), String.format(DEST, 2, "alice_and_filled_out_by_bob"), "approved_bob", "Read and Approved by Bob");
		app.sign(BOB, String.format(DEST, 2, "alice_and_filled_out_by_bob"), "sig2", String.format(DEST, 3, "alice_and_bob"));
		app.fillOut(String.format(DEST, 3, "alice_and_bob"), String.format(DEST, 4, "alice_and_bob_filled_out_by_carol"), "approved_carol", "Read and Approved by Carol");
		app.sign(CAROL, String.format(DEST, 4, "alice_and_bob_filled_out_by_carol"), "sig3", String.format(DEST, 5, "alice_bob_and_carol"));
		app.fillOutAndSign(DAVE, String.format(DEST, 5, "alice_bob_and_carol"), "sig4", "approved_dave", "Read and Approved by Dave", String.format(DEST, 6, "alice_bob_carol_and_dave"));
	}
}
