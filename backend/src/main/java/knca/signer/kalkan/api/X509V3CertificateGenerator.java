package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanProxy;

import java.security.cert.X509Certificate;

/**
 * Interface for Kalkan X509V3CertificateGenerator
 * Provides methods to generate signed X.509 certificates
 */
public interface X509V3CertificateGenerator {

    // ======= Public API Methods =======

    KalkanProxy getProxy();

    /**
     * Set the signature algorithm to be used for signing
     */
    default void setSignatureAlgorithm(String signatureAlgorithm) {
        KalkanAdapter.setSignatureAlgorithm(getProxy(), signatureAlgorithm);
    }

    /**
     * Generate the final X.509 certificate from TBS certificate and signature
     */
    default X509Certificate generate(Object tbsCert, byte[] signature) {
        KalkanProxy kalkanProxy = KalkanAdapter.generateCertificate(getProxy(), tbsCert, signature);
        return kalkanProxy.genericValue();
    }
}
