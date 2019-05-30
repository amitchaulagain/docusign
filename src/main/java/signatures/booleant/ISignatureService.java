package signatures.booleant;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.TextField;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface ISignatureService {

    PdfFormField createSignatureField(String name, PdfWriter writer, Rectangle rectangle);

    TextField createTextField(String name, PdfWriter writer, Rectangle rectangle, String value) throws IOException, DocumentException;

    void fillOut(String src, String dest, String name, String value) throws IOException, DocumentException;

    void sign(String keystore,
              String src, String name, String dest)
            throws GeneralSecurityException, IOException, DocumentException;

    void verifySignatures(String path) throws IOException, GeneralSecurityException;


}
