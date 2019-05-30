package signatures.booleant;

import sun.security.util.DerOutputStream;
import sun.security.x509.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;


public class Apple {
    static String MY_SECRET_ENTRY = "amit";
    private static final String MY_PRIVATE_KEY = "myPrivateKey";
    private static final String MY_CERTIFICATE = "myCertificate";
    private static final String DN_NAME = "CN=amit, OU=bol, O=bol, L=ktm, ST=test, C=CY";
    private static final String SHA1WITHRSA = "SHA1withRSA";


    void setCertificateEntry(String alias, Certificate certificate, KeyStore ks) throws KeyStoreException {
        ks.setCertificateEntry(alias, certificate);
    }

    Certificate getCertificate(String MY_SECRET_ENTRY, KeyStore ks) throws KeyStoreException {
        return ks.getCertificate(MY_SECRET_ENTRY);
    }


    public X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
            throws GeneralSecurityException, IOException {
        PrivateKey privkey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorith, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }


    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509CertInfo certInfo = new X509CertInfo();
        // Serial number and version
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

        // Subject & Issuer
        X500Name owner = new X500Name(DN_NAME);
        certInfo.set(X509CertInfo.SUBJECT, owner);
        certInfo.set(X509CertInfo.ISSUER, owner);

        // Key and algorithm
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));

        // Validity
        Date validFrom = new Date();
        Date validTo = new Date(validFrom.getTime() + 50L * 365L * 24L * 60L * 60L * 1000L); //50 years
        CertificateValidity validity = new CertificateValidity(validFrom, validTo);
        certInfo.set(X509CertInfo.VALIDITY, validity);

        GeneralNameInterface dnsName = new DNSName("baeldung.com");
        DerOutputStream dnsNameOutputStream = new DerOutputStream();
        dnsName.encode(dnsNameOutputStream);

        GeneralNameInterface ipAddress = new IPAddressName("127.0.0.1");
        DerOutputStream ipAddressOutputStream = new DerOutputStream();
        ipAddress.encode(ipAddressOutputStream);

        GeneralNames generalNames = new GeneralNames();
        generalNames.add(new GeneralName(dnsName));
        generalNames.add(new GeneralName(ipAddress));

        CertificateExtensions ext = new CertificateExtensions();
        ext.set(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension(generalNames));

        certInfo.set(X509CertInfo.EXTENSIONS, ext);

        // Create certificate and sign it
        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(keyPair.getPrivate(), SHA1WITHRSA);

        // Since the SHA1withRSA provider may have a different algorithm ID to what we think it should be,
        // we need to reset the algorithm ID, and resign the certificate
        AlgorithmId actualAlgorithm = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, actualAlgorithm);
        X509CertImpl newCert = new X509CertImpl(certInfo);
        newCert.sign(keyPair.getPrivate(), SHA1WITHRSA);


        return newCert;
    }

    private X509Certificate generateSelfSigned(KeyPair keyPair, String DN_NAME) throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509CertInfo certInfo = new X509CertInfo();
        // Serial number and version
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

        // Subject & Issuer
        X500Name owner = new X500Name(DN_NAME);
        certInfo.set(X509CertInfo.SUBJECT, owner);
        certInfo.set(X509CertInfo.ISSUER, owner);

        // Key and algorithm
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));

        // Validity
        Date validFrom = new Date();
        Date validTo = new Date(validFrom.getTime() + 50L * 365L * 24L * 60L * 60L * 1000L); //50 years
        CertificateValidity validity = new CertificateValidity(validFrom, validTo);
        certInfo.set(X509CertInfo.VALIDITY, validity);

//        GeneralNameInterface dnsName = new DNSName("baeldung.com");
//        DerOutputStream dnsNameOutputStream = new DerOutputStream();
//        dnsName.encode(dnsNameOutputStream);
//
//        GeneralNameInterface ipAddress = new IPAddressName("127.0.0.1");
//        DerOutputStream ipAddressOutputStream = new DerOutputStream();
//        ipAddress.encode(ipAddressOutputStream);
//
//        GeneralNames generalNames = new GeneralNames();
//        generalNames.add(new GeneralName(dnsName));
//        generalNames.add(new GeneralName(ipAddress));
//
//        CertificateExtensions ext = new CertificateExtensions();
//        ext.set(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension(generalNames));
//
//        certInfo.set(X509CertInfo.EXTENSIONS, ext);

        // Create certificate and sign it
        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(keyPair.getPrivate(), SHA1WITHRSA);

        // Since the SHA1withRSA provider may have a different algorithm ID to what we think it should be,
        // we need to reset the algorithm ID, and resign the certificate
        AlgorithmId actualAlgorithm = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, actualAlgorithm);
        X509CertImpl newCert = new X509CertImpl(certInfo);
        newCert.sign(keyPair.getPrivate(), SHA1WITHRSA);


        return newCert;
    }


    public static void main(String[] args) throws Exception, CertificateException {
        System.out.println("hl");


        String KEYSTORE_PWD = "11";
        String KEYSTORE_NAME = "amitstore";
        String KEY_STORE_TYPE = "JCEKS";


//        generate key
        KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA256");
        SecretKey mySecretKey = keygen.generateKey();


//        get JCEKS instance, note JKS has bug for non-private key
        KeyStore ks = KeyStore.getInstance("JCEKS");


//        create password
        char[] password = KEYSTORE_PWD.toCharArray();


//        Loads the empty keystore
        ks.load(null, password);


//        secret key entry and protection password
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

//


        // store the keystore
        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(KEYSTORE_NAME);
            ks.store(fos, password);
        } finally {
            if (fos != null) {
                fos.close();
            }
        }

        Apple a = new Apple();


        String distinguishedName = "CN=Hitesh Jha, L=London, C=GB";
//        Certificate certificate = a.generateCertificate(distinguishedName, keyPair, 365, "SHA256withRSA");
        System.out.println("it worked!");


//        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
//                ks.getEntry("privateKeyAlias", protParam);
//        PrivateKey myPrivateKey = pkEntry.getPrivateKey();


        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate a self signed certificate
        X509Certificate certificate = a.generateSelfSigned(keyPair, DN_NAME);
        X509Certificate certificate1 = a.generateSelfSigned(keyPair, "CN=gohar, OU=bol, O=bol, L=ktm, ST=test, C=CY");


        X509Certificate[] certificateChain = new X509Certificate[2];
        certificateChain[0] = certificate;

        certificateChain[1] = certificate1;
        ks.setKeyEntry(MY_PRIVATE_KEY, keyPair.getPrivate(), password, certificateChain);


        X509Certificate[] certificateChain2 = new X509Certificate[1];
        X509Certificate certificate2 = a.generateSelfSigned(keyPair, "CN=jal, OU=jal, O=jal, L=ktm, ST=test, C=CY");


        certificateChain2[0] = certificate2;
        ks.setKeyEntry("hero", keyPair.getPrivate(), password, certificateChain2);

        X509Certificate hero_certificate = a.generateSelfSigned(keyPair, "CN=atif aslam, OU=bol, O=bol, L=ktm, ST=test, C=CY");

        ks.setCertificateEntry("lala", hero_certificate);


        java.io.FileOutputStream fosi = null;
        try {
            fos = new java.io.FileOutputStream("aadat");
            ks.store(fos, password);
        } finally {
            if (fos != null) {
                fos.close();
            }
        }


        System.out.println("success");


    }


}
