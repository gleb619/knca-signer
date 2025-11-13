package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanProxy;
import knca.signer.kalkan.ReflectionHelper;

import java.security.PublicKey;
import java.util.Date;

/**
 * Interface for TBS Certificate management operations
 * Encapsulates V3TBSCertificateGenerator operations and DER encoding workflow
 */
public interface TBSCertificateManager {

    KalkanProxy getProxy();

    /**
     * Set certificate serial number
     */
    default void setSerialNumber(byte[] serialNumber) {
        KalkanProxy derInteger = KalkanAdapter.createDERInteger(serialNumber);
        getProxy().invokeScript("realObject.setSerialNumber(args[0])", derInteger);
    }

    /**
     * Set certificate signature algorithm
     */
    default void setSignature(String signatureAlgorithm) {
        KalkanProxy derObjectIdentifier = KalkanAdapter.createDERObjectIdentifier(signatureAlgorithm);
        KalkanProxy derNull = KalkanAdapter.createDERNull();
        KalkanProxy algorithmIdentifier = KalkanAdapter.createAlgorithmIdentifier(derObjectIdentifier, derNull);
        getProxy().invokeScript("realObject.setSignature(args[0])", algorithmIdentifier);
    }

    /**
     * Set certificate issuer
     */
    default void setIssuer(String issuerDN) {
        KalkanProxy x509Name = KalkanAdapter.createX509Name(issuerDN);
        getProxy().invokeScript("realObject.setIssuer(args[0])", x509Name);
    }

    /**
     * Set certificate subject
     */
    default void setSubject(String subjectDN) {
        KalkanProxy x509Name = KalkanAdapter.createX509Name(subjectDN);
        getProxy().invokeScript("realObject.setSubject(args[0])", x509Name);
    }

    /**
     * Set subject public key info
     */
    default void setSubjectPublicKeyInfo(PublicKey publicKey) {
        KalkanProxy subjPubKeyInfo = KalkanAdapter.createSubjectPublicKeyInfo(publicKey);
        getProxy().invokeScript("realObject.setSubjectPublicKeyInfo(args[0])", subjPubKeyInfo);
    }

    /**
     * Set certificate validity start date
     */
    default void setStartDate(Date startDate) {
        KalkanProxy time = KalkanAdapter.createTime(startDate);
        getProxy().invokeScript("realObject.setStartDate(args[0])", time);
    }

    /**
     * Set certificate validity end date
     */
    default void setEndDate(Date endDate) {
        KalkanProxy time = KalkanAdapter.createTime(endDate);
        getProxy().invokeScript("realObject.setEndDate(args[0])", time);
    }

    /**
     * Set certificate extensions
     */
    default void setExtensions(Object extensions) {
        getProxy().invokeScript("realObject.setExtensions(args[0])", extensions);
    }

    /**
     * Generate the TBS certificate
     */
    default KalkanProxy generateTBSCertificate() {
        return getProxy().invokeScript("realObject.generateTBSCertificate()");
    }

    /**
     * Get DER encoded bytes from TBS certificate
     */
    default byte[] getDEREncoded(Object tbsCertificate) {
        if (tbsCertificate instanceof KalkanProxy proxy) {
            // If it's already a proxy, invoke directly
            KalkanProxy result = proxy.invokeScript("args[0].getDEREncoded()", tbsCertificate);
            return result.genericValue();
        } else {
            // For raw objects, use ReflectionHelper instead of simple reflection
            Object unwrapped = ReflectionHelper.unwrapValue(tbsCertificate);
            return (byte[]) ReflectionHelper.invokeMethod(unwrapped, "getDEREncoded", null, null);
        }
    }
}
