/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.booleant;

import com.itextpdf.text.*;
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

public class Hero {
    public static final String FORM = "src/main/resources/results/input/sample.pdf";
    public static final String ALICE = "src/main/resources/alice";
    public static final String BOB = "src/main/resources/bob";
    public static final String CAROL = "src/main/resources/carol";
    public static final String DAVE = "src/main/resources/dave";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String DEST = "src/main/resources/results/output/done.pdf";

    public static final String AMIT = "src/main/resources/amit";
    public static final String HITESH = "src/main/resources/hitesh";



    public void certify(String keystore,
                        String src, String name,  String dest)
            throws GeneralSecurityException, IOException, DocumentException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = (String) ks.aliases().nextElement();
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
        String alias = (String) ks.aliases().nextElement();
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
    public void signJCEKS(String keystore,
                     String src, String name, String dest)
            throws GeneralSecurityException, IOException, DocumentException {


        KeyStore ks = KeyStore.getInstance("jceks");
        ks.load(new FileInputStream(keystore), "11".toCharArray());
        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, "11".toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src)   ;
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


    public void fillOutMessage(String src, String field, String message, String dest)
            throws IOException, DocumentException {

        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);


        PdfStamper stamper = new PdfStamper(reader, os);
        stamper.getAcroFields().setField(field, message);


        // Creating the appearance

    }


    public void fillOutAndSign(String keystore,
                               String src, String name, String fname, String value, String dest)
            throws GeneralSecurityException, IOException, DocumentException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = (String) ks.aliases().nextElement();
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


    public PdfFormField createSignatureField(String name, PdfWriter writer, Rectangle rectangle) throws IOException {

        PdfFormField field = PdfFormField.createSignature(writer);
        field.setFieldName(name);
        // set the widget properties
        field.setPage();
        field.setWidget(rectangle, PdfAnnotation.HIGHLIGHT_INVERT);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        // add it as an annotation
        writer.addAnnotation(field);
        return field;

    }

    public TextField createTextField(String name, PdfWriter writer, Rectangle rectangle, String value) throws IOException, DocumentException {

        TextField text = new TextField(writer, rectangle, name);

        text.setText(value);
        text.setFontSize(10);
        //field.setFieldName(name);
        // set the widget properties

        // add it as an annotation
        writer.addAnnotation(text.getTextField());
        return text;

    }


    public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        Hero app = new Hero();

        Document document = new Document(PageSize.A4);
        PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(DEST));
        document.open();
        PdfContentByte cb = writer.getDirectContent();

// Load existing PDF
        PdfReader reader = new PdfReader(new FileInputStream(FORM));
        PdfImportedPage page = writer.getImportedPage(reader, 1);

// Copy first page of existing PDF into output PDF
        document.newPage();
        cb.addTemplate(page, 0, 0);

// Add your new data / text here
// for example...

        PdfFormField signature1 = app.createSignatureField("sig1", writer, new Rectangle(0, 0, 100, 100));
        PdfFormField signature2 = app.createSignatureField("sig2", writer, new Rectangle(0, 100, 100, 200));
        PdfFormField signature3 = app.createSignatureField("sig3", writer, new Rectangle(0, 200, 100, 300));

        document.add(new Paragraph("my timestamp"));


        TextField xx = app.createTextField("message_alice", writer, new Rectangle(0, 500, 100, 520), "Message from Alice");

        TextField yy = app.createTextField("message_bob", writer, new Rectangle(0, 530, 100, 550), "Message from Bob");

        TextField zz = app.createTextField("message_carol", writer, new Rectangle(0, 560, 100, 580), "Message from Carol");


        document.close();


        //app.createForm();

        app.fillOut("src/main/resources/results/output/done.pdf", "src/main/resources/results/output/done1.pdf", "message_alice", "alice signed it");

        app.certify(ALICE, "src/main/resources/results/output/done1.pdf", "sig1", "src/main/resources/results/output/hero.pdf");


//        app.fillOut(String.format(DEST, 1, "alice"), String.format(DEST, 2, "alice_and_filled_out_by_bob"), "approved_bob", "Read and Approved by Bob");

        app.signJCEKS(AMIT, "src/main/resources/results/output/hero.pdf", "sig2", "src/main/resources/results/output/all_signed.pdf");
//        app.fillOut(String.format(DEST, 3, "alice_and_bob"), String.format(DEST, 4, "alice_and_bob_filled_out_by_carol"), "approved_carol", "Read and Approved by Carol");
//        app.fillOutAndSign(DAVE, String.format(DEST, 5, "alice_bob_and_carol"), "sig4", "approved_dave", "Read and Approved by Dave", String.format(DEST, 6, "alice_bob_carol_and_dave"));
        app.signJCEKS(HITESH, "src/main/resources/results/output/all_signed.pdf", "sig3", "src/main/resources/results/output/final_hitesh_signed.pdf");
    }


}
