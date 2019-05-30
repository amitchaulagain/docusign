package signatures.booleant;

import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

public class KeyStoreService implements IKeyStoreService {

    private final KeyStore keyStore;
    private final String type = "JCEKS";


    KeyStoreService(String name, String password) throws CertificateException, NoSuchAlgorithmException, IOException {

        this.keyStore = loadKeyStore(name, password, this.type);
    }


    @Override
    public KeyStore createKeyStore(String name, String password, String type) throws KeyStoreException, CertificateException, NoSuchAlgorithmException,
            IOException {
        KeyStore keyStore = null;
        if (type == null || type.isEmpty()) {
            type = KeyStore.getDefaultType();
        }
        keyStore = KeyStore.getInstance(type);
        //load
        char[] pwdArray = password.toCharArray();
        keyStore.load(null, pwdArray);

        // Save the keyStore
        FileOutputStream fos = new FileOutputStream(name);
        keyStore.store(fos, pwdArray);
        fos.close();
        return keyStore;
    }

    @Override
    public KeyStore loadKeyStore(String name, String password, String type) throws IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = null;
        char[] pwdArray = password.toCharArray();
        keyStore.load(new FileInputStream(name), pwdArray);
        return keyStore;
    }

    @Override
    public void deleteKeyStore(String name, String password, String type) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore keyStore = loadKeyStore(name, password, type);
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            keyStore.deleteEntry(alias);
        }
        keyStore = null;
    }

    public X509Certificate generateCertificate(KeyPair keyPair, CertificateUser distinguishedName, CertificateUser issuer) throws CertificateException,
            IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        final String SHA1WITHRSA = "SHA1withRSA";
        X509CertInfo certInfo = new X509CertInfo();
        // Serial number and version
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

        // Subject & Issuer
        X500Name owner = new X500Name(distinguishedName.toString());
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

    @Override
    public void removeCertificate(String name, String password, String alias) throws CertificateException, NoSuchAlgorithmException, IOException,
            KeyStoreException {
        KeyStore keyStore = loadKeyStore(name, password, this.type);

        keyStore.deleteEntry(alias);
    }


    public void setKeyEntry(String name, String password, String alias, PrivateKey privateKey, String keyPassword, java.security.cert.Certificate[]
            certificateChain) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
//        KeyStore keyStore = null;
//        keyStore.load(new FileInputStream(name), password.toCharArray());
        keyStore.setKeyEntry(alias, privateKey, keyPassword.toCharArray(), certificateChain);
    }

    public void setCertificateEntry(String name, String password, String alias, java.security.cert.Certificate certificate) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
//        KeyStore keyStore = null;
//        keyStore.load(new FileInputStream(name), password.toCharArray());
        keyStore.setCertificateEntry(alias, certificate);
    }

    public Certificate getCertificate(String name, String password, String alias) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
//        KeyStore keyStore = null;
//        keyStore.load(new FileInputStream(name), password.toCharArray());

        return keyStore.getCertificate(alias);
    }

    @Override
    public KeyStore.Entry getKeyEntry(String alias, String keyPassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableEntryException {
        KeyStore.Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        return entry;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
