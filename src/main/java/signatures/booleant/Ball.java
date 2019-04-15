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
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfImportedPage;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class Ball {

    public static void main(String args[]) throws DocumentException, IOException {

        FileOutputStream outputStream;
        outputStream = new FileOutputStream("src/main/resources/results/output/hello_output.pdf");

        // Create output PDF
        Document document = new Document(PageSize.A4);
        PdfWriter writer = PdfWriter.getInstance(document, outputStream);
        document.open();
        PdfContentByte cb = writer.getDirectContent();

// Load existing PDF
        FileInputStream templateInputStream= new FileInputStream("src/main/resources/results/input/hello.pdf");
        PdfReader reader = new PdfReader(templateInputStream);
        PdfImportedPage page = writer.getImportedPage(reader, 1);

// Copy first page of existing PDF into output PDF
       // document.newPage();
        cb.addTemplate(page, 100, 0);

// Add your new data / text here
// for example...
        document.add(new Paragraph("my timestamp"));

        document.close();

    }


}
