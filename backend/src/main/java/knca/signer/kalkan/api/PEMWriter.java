package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanProxy;

/**
 * Interface for Kalkan PEMWriter
 * Provides methods to write cryptographic objects in PEM format
 */
public interface PEMWriter {

    // ======= Public API Methods =======

    KalkanProxy getProxy();

    /**
     * Write an object in PEM format
     */
    default void writeObject(Object obj) {
        getProxy().invokeScript(
                "realObject.writeObject(args[0])", obj);
    }

    /**
     * Flush pending write operations
     */
    default void flush() {
        getProxy().invokeScript(
                "realObject.flush()");
    }
}
