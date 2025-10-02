package knca.signer.service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Utility class for managing keystores (PKCS12 and JKS).
 */
public class KeyStoreManager {

    /**
     * Create a PKCS12 keystore with the given private key and certificate chain.
     */
    public static void createPKCS12Keystore(PrivateKey privateKey, X509Certificate userCert,
                                            X509Certificate caCert, String filename,
                                            String password, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KALKAN");
        keyStore.load(null, null);

        // Create certificate chain
        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{userCert, caCert};

        // Store private key and certificate chain
        keyStore.setKeyEntry("user", privateKey, password.toCharArray(), chain);

        // Save keystore
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Create a JKS keystore with the given private key and certificate chain.
     */
    public static void createJKSKeystore(PrivateKey privateKey, X509Certificate userCert,
                                         X509Certificate caCert, String filename,
                                         String password, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        // Create certificate chain
        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{userCert, caCert};

        // Store private key and certificate chain
        keyStore.setKeyEntry("user", privateKey, password.toCharArray(), chain);

        // Save keystore
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Load a private key and certificate from a PKCS12 keystore.
     */
    public static PrivateKey loadPrivateKeyFromPKCS12(String filename, String password,
                                                      String alias, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", providerName);
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        }
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    /**
     * Load a certificate from a PKCS12 keystore.
     */
    public static X509Certificate loadCertificateFromPKCS12(String filename, String password,
                                                            String alias, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", providerName);
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Load certificate chain from a PKCS12 keystore.
     */
    public static java.security.cert.Certificate[] loadCertificateChainFromPKCS12(String filename,
                                                                                  String password, String alias,
                                                                                  String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", providerName);
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        }
        return keyStore.getCertificateChain(alias);
    }
}
