package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.KalkanProxy;

/**
 * Interface for Kalkan X509ExtensionsGenerator
 * Provides methods to build certificate extensions collections
 */
public interface X509ExtensionsGenerator {

    // ======= Public API Methods =======

    KalkanProxy getProxy();

    /**
     * Add an extension using a DEREncodable value
     */
    @SuppressWarnings("unused")
    default void addExtension(String oid, boolean critical, Object value) {
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        getProxy().invokeScript(
                "realObject.addExtension(args[0], args[1], args[2])", derOid, critical, value);
    }

    /**
     * Add an extension using raw byte value
     */
    @SuppressWarnings("unused")
    default void addExtension(String oid, boolean critical, byte[] value) {
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        getProxy().invokeScript(
                "realObject.addExtension(args[0], args[1], args[2])", derOid, critical, value);
    }

    /**
     * Add a BasicConstraints extension
     */
    default void addExtension(String oid, boolean critical, boolean booleanValue) {
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        KalkanProxy basicConstraints = KalkanAdapter.createBasicConstraints(booleanValue);
        getProxy().invokeScript(
                "realObject.addExtension(args[0], args[1], args[2])", derOid, critical, basicConstraints);
    }

    /**
     * Add a KeyUsage extension
     */
    default void addExtension(String oid, boolean critical, int keyUsage) {
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        KalkanProxy keyUsageObj = KalkanAdapter.createKeyUsage(keyUsage);
        getProxy().invokeScript(
                "realObject.addExtension(args[0], args[1], args[2])", derOid, critical, keyUsageObj);
    }

    /**
     * Add an extension using a KalkanProxy value
     */
    default void addExtension(String oid, boolean critical, KalkanProxy extensionValue) {
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        getProxy().invokeScript(
                "realObject.addExtension(args[0], args[1], args[2])", derOid, critical, extensionValue);
    }

    /**
     * Add an ExtendedKeyUsage extension for email protection
     * @param id - a oid of certificate purpose
     */
    default void addExtendedKeyUsageEmailProtection(String id) {
        KalkanProxy eku = KalkanAdapter.createDERSequence(KalkanAdapter.createDERObjectIdentifier(id));
        addExtension(KalkanConstants.X509Extensions.ExtendedKeyUsage, false, eku);
    }

    /**
     * Generate the final X509Extensions object
     */
    default KalkanProxy generate() {
        return getProxy().invokeScript(
                "realObject.generate()");
    }

    /**
     * Add Subject Alternative Name extension
     */
    default void addSubjectAlternativeName(KalkanProxy sanVector) {
        KalkanProxy sanSequence = KalkanAdapter.createDERSequence(sanVector);
        KalkanProxy sanGeneralNames = KalkanAdapter.createGeneralNames(sanSequence);
        addExtension(KalkanConstants.X509Extensions.SubjectAlternativeName, false, sanGeneralNames);
    }
}
