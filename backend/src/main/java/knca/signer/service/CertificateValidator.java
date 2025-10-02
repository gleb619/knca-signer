package knca.signer.service;

import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility class for certificate validation operations.
 */
@Slf4j
public class CertificateValidator {

    /**
     * Validate a certificate against a CA certificate.
     */
    public static void validateCertificate(X509Certificate userCert, X509Certificate caCert) throws Exception {
        // Verify certificate signature
        userCert.verify(caCert.getPublicKey());

        // Check validity
        userCert.checkValidity();

        log.info("Certificate validated successfully against CA");
    }

    /**
     * Load CA certificate from file.
     */
    public static X509Certificate loadCACertificate(String caCertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(caCertPath)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Validate certificate chain.
     */
    public static void validateCertificateChain(X509Certificate[] chain, X509Certificate caCert) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Certificate chain is empty");
        }

        // Validate each certificate in the chain
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate cert = chain[i];
            X509Certificate issuer = chain[i + 1];
            cert.verify(issuer.getPublicKey());
            cert.checkValidity();
        }

        // Validate the root certificate against CA if it's not self-signed
        X509Certificate rootCert = chain[chain.length - 1];
        if (!rootCert.getSubjectDN().equals(rootCert.getIssuerDN())) {
            rootCert.verify(caCert.getPublicKey());
        }
        rootCert.checkValidity();

        log.info("Certificate chain validated successfully");
    }
}
