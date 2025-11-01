package knca.signer.service;

import knca.signer.kalkan.KalkanAdapter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Utility class for managing keystores (PKCS12 and JKS).
 * Now uses Kalkan-compatible keystore creation for real application compatibility.
 */
@Slf4j
public class KeyStoreManager {

    /**
     * Create a PKCS12 keystore with the given private key and certificate chain.
     * Uses Kalkan-compatible creation first, with fallback to JVM keystore conversion if needed.
     * This ensures compatibility with real Kalkan applications that expect JDKPKCS12KeyStore.BCPKCS12KeyStore format.
     */
    public static void createPKCS12Keystore(PrivateKey privateKey, X509Certificate userCert,
                                            X509Certificate caCert, String filename,
                                            String password, String providerName) throws Exception {
        try {
            // Try Kalkan-compatible PKCS12 creation first (direct SPI instantiation)
            createPKCS12KeystoreViaKalkan(privateKey, userCert, caCert, filename, password, providerName);
            log.info("Successfully created Kalkan-compatible PKCS12 keystore: {}", filename);
        } catch (Exception e) {
            // Kalkan direct creation failed, try JVM-based conversion approach
            log.warn("Kalkan PKCS12 creation failed, falling back to JVM keystore conversion: {}", e.getMessage());
            createPKCS12ViaConversion(privateKey, userCert, caCert, filename, password, providerName);
        }
    }

    /**
     * Create PKCS12 keystore using Kalkan's direct SPI instantiation.
     * This creates keystores that are identical to those created by real Kalkan applications.
     */
    private static void createPKCS12KeystoreViaKalkan(PrivateKey privateKey, X509Certificate userCert,
                                                      X509Certificate caCert, String filename,
                                                      String password, String providerName) throws Exception {
        // Create Kalkan-compatible PKCS12 keystore instance
        var pkcs12Proxy = KalkanAdapter.createKalkanPKCS12Keystore();

        // Create certificate chain
        Certificate[] chain = new Certificate[]{userCert, caCert};

        // Store private key and certificate chain using MVEL script
        pkcs12Proxy.invokeScript("realObject.engineSetKeyEntry(alias, key, password, chain)",
                "user", privateKey, password.toCharArray(), chain);

        // Save keystore to file using MVEL script
        try (FileOutputStream fos = new FileOutputStream(new File(filename))) {
            pkcs12Proxy.invokeScript("realObject.engineStore(stream, password)", fos, password.toCharArray());
        }
    }

    /**
     * Create PKCS12 keystore directly using Kalkan provider.
     */
    @Deprecated(forRemoval = true)
    private static void createPKCS12KeystoreDirect(PrivateKey privateKey, X509Certificate userCert,
                                                   X509Certificate caCert, String filename,
                                                   String password, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", providerName);
        keyStore.load(null, null);

        // Create certificate chain
        Certificate[] chain = new Certificate[]{userCert, caCert};

        // Store private key and certificate chain
        keyStore.setKeyEntry("user", privateKey, password.toCharArray(), chain);

        // Save keystore
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    /**
     * Create PKCS12 keystore via conversion: JKS -> PKCS12 using Kalkan provider.
     * This ensures compatibility by using a proven working format conversion.
     */
    private static void createPKCS12ViaConversion(PrivateKey privateKey, X509Certificate userCert,
                                                  X509Certificate caCert, String filename,
                                                  String password, String providerName) throws Exception {
        // Step 1: Create temporary JKS keystore using standard JVM
        String tempJksFile = "%s.temp.jks".formatted(filename);
        try {
            KeyStore jksKeyStore = KeyStore.getInstance("JKS");
            jksKeyStore.load(null, null);

            Certificate[] chain = new Certificate[]{userCert, caCert};
            jksKeyStore.setKeyEntry("user", privateKey, password.toCharArray(), chain);

            try (FileOutputStream fos = new FileOutputStream(tempJksFile)) {
                jksKeyStore.store(fos, password.toCharArray());
            }

            // Step 2: Load JKS and convert to PKCS12 using Kalkan provider
            jksKeyStore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(tempJksFile)) {
                jksKeyStore.load(fis, password.toCharArray());
            }

            // Get the entry from JKS
            PrivateKey pk = (PrivateKey) jksKeyStore.getKey("user", password.toCharArray());
            Certificate[] certChain = jksKeyStore.getCertificateChain("user");

            // Create PKCS12 with Kalkan provider
            KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12", providerName);
            pkcs12KeyStore.load(null, null);
            pkcs12KeyStore.setKeyEntry("user", pk, password.toCharArray(), certChain);

            // Save the PKCS12 keystore
            try (FileOutputStream fos = new FileOutputStream(filename)) {
                pkcs12KeyStore.store(fos, password.toCharArray());
            }

        } finally {
            // Cleanup temporary file
            Files.deleteIfExists(java.nio.file.Paths.get(tempJksFile));
        }
    }

    /**
     * Create a JKS keystore with the given private key and certificate chain.
     * Uses Kalkan-compatible creation first, with fallback to JVM keystore if needed.
     * This ensures compatibility with real Kalkan applications that expect JavaKeyStore.JKS format.
     */
    public static void createJKSKeystore(PrivateKey privateKey, X509Certificate userCert,
                                         X509Certificate caCert, String filename,
                                         String password, String providerName) throws Exception {
        try {
            createJKSKeystoreViaKalkan(privateKey, userCert, caCert, filename, password, providerName);
            log.info("Successfully created Kalkan-compatible JKS keystore: {}", filename);
        } catch (Exception e) {
            // Kalkan direct creation failed, try JVM-based approach
            log.warn("Kalkan JKS creation failed, falling back to JVM keystore: {}", e.getMessage());
            createJKSKeystoreViaJVM(privateKey, userCert, caCert, filename, password, providerName);
        }
    }

    /**
     * Create JKS keystore using Kalkan's direct SPI instantiation.
     * This creates keystores that are identical to those created by real Kalkan applications.
     */
    private static void createJKSKeystoreViaKalkan(PrivateKey privateKey, X509Certificate userCert,
                                                   X509Certificate caCert, String filename,
                                                   String password, String providerName) throws Exception {
        var jksProxy = KalkanAdapter.createKalkanJKSKeystore();
        Certificate[] chain = new Certificate[]{userCert, caCert};

        jksProxy.invokeScript("realObject.engineSetKeyEntry(alias, key, password, chain)",
                "user", privateKey, password.toCharArray(), chain);

        try (FileOutputStream fos = new FileOutputStream(new File(filename))) {
            jksProxy.invokeScript("realObject.engineStore(stream, password)", fos, password.toCharArray());
        }
    }

    /**
     * Create a JKS keystore with the given private key and certificate chain (JVM fallback).
     */
    private static void createJKSKeystoreViaJVM(PrivateKey privateKey, X509Certificate userCert,
                                                X509Certificate caCert, String filename,
                                                String password, String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        // Create certificate chain
        Certificate[] chain = new Certificate[]{userCert, caCert};

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
    @Deprecated(forRemoval = true)
    public static Certificate[] loadCertificateChainFromPKCS12(String filename,
                                                                                  String password, String alias,
                                                                                  String providerName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", providerName);
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        }
        return keyStore.getCertificateChain(alias);
    }
}
