package signatures.booleant;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface IKeyStoreService {

    KeyStore createKeyStore(String name, String password, String type) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException;

    KeyStore loadKeyStore(String name, String password, String type) throws IOException, CertificateException, NoSuchAlgorithmException;

    void deleteKeyStore(String name, String password, String type) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException;


    X509Certificate generateCertificate(KeyPair keyPair, CertificateUser owner, CertificateUser issuer) throws CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    //
//    void generateSelfSignedCertificate();
//
//
    void removeCertificate(String name, String password, String alias) throws CertificateException, NoSuchAlgorithmException, IOException,
            KeyStoreException;

    //
    void setKeyEntry(String name, String password, String alias, PrivateKey privateKey, String keyPassword, java.security.cert.Certificate[] certificateChain)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException;
//

    void setCertificateEntry(String name, String password, String alias, java.security.cert.Certificate certificate) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException;

    Certificate getCertificate(String name, String password, String alias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException;

    KeyStore.Entry getKeyEntry(String alias,String keyPassword)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException;
}
