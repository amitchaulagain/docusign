/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.booleant;

import sun.security.x509.CertificateValidity;

public class CertificateInfo {
    CertificateUser subject;
    CertificateUser owner;
    String key;
    CertificateValidity certificateValidity;


}
