package signatures.booleant;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;

public class SignatureService implements ISignatureService {


    @Override
    public PdfFormField createSignatureField(String name, PdfWriter writer, Rectangle rectangle) {
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

    @Override
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

    @Override
    public void fillOut(String src, String dest, String name, String value) throws IOException, DocumentException {
        PdfReader reader = new PdfReader(src);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
        AcroFields form = stamper.getAcroFields();
        form.setField(name, value);
        form.setFieldProperty(name, "setfflags", PdfFormField.FF_READ_ONLY, null);
        stamper.close();
    }

    @Override
    public void sign(String keystore, String src, String name, String dest) throws GeneralSecurityException, IOException, DocumentException {
        KeyStore ks = KeyStore.getInstance("jceks");
        ks.load(new FileInputStream(keystore), "11".toCharArray());
        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, "11".toCharArray());
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
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    @Override
    public void verifySignatures(String path) throws IOException, GeneralSecurityException {
        System.out.println(path);
        PdfReader reader = new PdfReader(path);
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        for (String name : names) {
            System.out.println("===== " + name + " =====");
            verifySignature(fields, name);
        }
        System.out.println();
    }

    public PdfPKCS7 verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
        System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(name));
        System.out.println("Document revision: " + fields.getRevision(name) + " of " + fields.getTotalRevisions());
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        System.out.println("Integrity check OK? " + pkcs7.verify());
        return pkcs7;
    }

    public void certify(String keystore, String src, String password, String name, String dest)
            throws GeneralSecurityException, IOException, DocumentException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), password.toCharArray());
        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password.toCharArray());
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
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }
}