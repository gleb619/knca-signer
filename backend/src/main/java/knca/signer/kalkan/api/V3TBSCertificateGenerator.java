package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanProxy;

import java.security.PublicKey;

/**
 * Interface for Kalkan V3TBSCertificateGenerator
 * Provides methods to build TBS certificate structures
 */
@Deprecated(forRemoval = true)
public interface V3TBSCertificateGenerator {

    // ======= Public API Methods =======

    KalkanProxy getProxy();

    /**
     * Set the certificate serial number from byte array
     */
    default void setSerialNumber(byte[] serialNumber) {
        KalkanProxy derInteger = KalkanAdapter.createDERInteger(serialNumber);
        getProxy().invokeScript(
                "realObject.setSerialNumber(args[0])", derInteger);
    }

    /**
     * Set the signature algorithm
     */
    default void setSignature(String signatureAlgorithm) {
        KalkanProxy algorithmIdentifier = KalkanAdapter.createAlgorithmIdentifier(KalkanAdapter.createDERObjectIdentifier(signatureAlgorithm), KalkanAdapter.createDERNull());
        getProxy().invokeScript(
                "realObject.setSignature(args[0])", algorithmIdentifier);
    }

    /**
     * Set the certificate issuer from string
     */
    default void setIssuer(String issuer) {
        KalkanProxy x509Name = KalkanAdapter.createX509Name(issuer);
        getProxy().invokeScript(
                "realObject.setIssuer(args[0])", x509Name);
    }

    /**
     * Set the certificate subject from string
     */
    default void setSubject(String subject) {
        KalkanProxy x509Name = KalkanAdapter.createX509Name(subject);
        getProxy().invokeScript(
                "realObject.setSubject(args[0])", x509Name);
    }

    /**
     * Set the subject public key info from public key
     */
    default void setSubjectPublicKeyInfo(PublicKey publicKey) throws Exception {
        KalkanProxy subjPubKeyInfo = KalkanAdapter.createSubjectPublicKeyInfo(publicKey);
        getProxy().invokeScript(
                "realObject.setSubjectPublicKeyInfo(args[0])", subjPubKeyInfo);
    }

    /**
     * Set the certificate validity start date
     */
    default void setStartDate(java.util.Date startDate) {
        KalkanProxy time = KalkanAdapter.createTime(startDate);
        getProxy().invokeScript(
                "realObject.setStartDate(args[0])", time);
    }

    /**
     * Set the certificate validity end date
     */
    default void setEndDate(java.util.Date endDate) {
        KalkanProxy time = KalkanAdapter.createTime(endDate);
        getProxy().invokeScript(
                "realObject.setEndDate(args[0])", time);
    }

    /**
     * Set the certificate extensions
     */
    default void setExtensions(Object extensions) {
        getProxy().invokeScript(
                "realObject.setExtensions(args[0])", extensions);
    }

    /**
     * Generate the TBS certificate structure
     */
    default Object generateTBSCertificate() {
        return getProxy().invokeScript(
                "realObject.generateTBSCertificate()");
    }
}
