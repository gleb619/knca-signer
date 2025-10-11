package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanProxy;

import java.security.PublicKey;

/**
 * Interface for Kalkan V3TBSCertificateGenerator
 * Provides methods to build TBS certificate structures
 */
public interface V3TBSCertificateGenerator {

    // ======= Public API Methods =======

    KalkanProxy getProxy();

    /**
     * Set the certificate serial number from byte array
     */
    default void setSerialNumber(byte[] serialNumber) {
        KalkanAdapter.setSerialNumber(getProxy(), serialNumber);
    }

    /**
     * Set the signature algorithm
     */
    default void setSignature(String signatureAlgorithm) {
        KalkanAdapter.setSignature(getProxy(), signatureAlgorithm);
    }

    /**
     * Set the certificate issuer from string
     */
    default void setIssuer(String issuer) {
        KalkanAdapter.setIssuer(getProxy(), issuer);
    }

    /**
     * Set the certificate subject from string
     */
    default void setSubject(String subject) {
        KalkanAdapter.setSubject(getProxy(), subject);
    }

    /**
     * Set the subject public key info from public key
     */
    default void setSubjectPublicKeyInfo(PublicKey publicKey) throws Exception {
        KalkanAdapter.setSubjectPublicKeyInfo(getProxy(), publicKey);
    }

    /**
     * Set the certificate validity start date
     */
    default void setStartDate(java.util.Date startDate) {
        KalkanAdapter.setStartDate(getProxy(), startDate);
    }

    /**
     * Set the certificate validity end date
     */
    default void setEndDate(java.util.Date endDate) {
        KalkanAdapter.setEndDate(getProxy(), endDate);
    }

    /**
     * Set the certificate extensions
     */
    default void setExtensions(Object extensions) {
        KalkanAdapter.setExtensions(getProxy(), extensions);
    }

    /**
     * Generate the TBS certificate structure
     */
    default Object generateTBSCertificate() {
        return KalkanAdapter.generateTBSCertificate(getProxy());
    }
}
