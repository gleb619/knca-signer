package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
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
    default void addExtension(String oid, boolean critical, Object value) {
        KalkanAdapter.addExtension(getProxy(), oid, critical, value);
    }

    /**
     * Add an extension using raw byte value
     */
    default void addExtension(String oid, boolean critical, byte[] value) {
        KalkanAdapter.addExtension(getProxy(), oid, critical, value);
    }

    /**
     * Add a BasicConstraints extension
     */
    default void addExtension(String oid, boolean critical, boolean booleanValue) {
        KalkanAdapter.addExtension(getProxy(), oid, critical, booleanValue);
    }

    /**
     * Add a KeyUsage extension
     */
    default void addExtension(String oid, boolean critical, int keyUsage) {
        KalkanAdapter.addExtension(getProxy(), oid, critical, keyUsage);
    }

    /**
     * Add an extension using a KalkanProxy value
     */
    default void addExtension(String oid, boolean critical, KalkanProxy extensionValue) {
        KalkanAdapter.addExtension(getProxy(), oid, critical, extensionValue);
    }

    /**
     * Add an ExtendedKeyUsage extension for email protection
     */
    default void addExtendedKeyUsageEmailProtection() {
        KalkanAdapter.addExtendedKeyUsageEmailProtection(getProxy());
    }

    /**
     * Generate the final X509Extensions object
     */
    default KalkanProxy generate() {
        return KalkanAdapter.generateExtensions(getProxy());
    }

    /**
     * Add Subject Alternative Name extension
     */
    default void addSubjectAlternativeName(KalkanProxy sanVector) {
        KalkanAdapter.addSubjectAlternativeName(getProxy(), sanVector);
    }
}
