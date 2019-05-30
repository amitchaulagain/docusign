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

public interface ISignatureService {

    PdfFormField createSignatureField(String name, PdfWriter writer, Rectangle rectangle);

    TextField createTextField(String name, PdfWriter writer, Rectangle rectangle, String value) throws IOException, DocumentException;

    void fillOut(String src, String dest, String name, String value) throws IOException, DocumentException;

    void sign(String keystore,
              String src, String name, String dest)
            throws GeneralSecurityException, IOException, DocumentException;

    void verifySignatures(String path) throws IOException, GeneralSecurityException;

    public void certify(String keystore,String password, String src, String name,  String dest)
            throws GeneralSecurityException, IOException, DocumentException;



}
