package knca.signer.kalkan.api;

import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.KalkanProxy;
import knca.signer.kalkan.KalkanProxy.ProxyArg;

/**
 * Interface for ASN1EncodableVector operations
 * Provides methods to build certificate extension vectors using script-based implementations
 */
public interface ASN1EncodableVector {

    KalkanProxy getProxy();

    default void add(Object item) {
        getProxy().invokeScript("realObject.add(args[0])", item);
    }

    default void addGeneralNameEmail(String email) {
        KalkanProxy generalName = KalkanAdapter.createGeneralName(KalkanConstants.GeneralName.rfc822Name, email);
        add(generalName);
    }

    default void addGeneralNameOtherName(String oid, String value) {
        // Inline the OtherName creation logic using existing proxy methods
        KalkanProxy derOid = KalkanAdapter.createDERObjectIdentifier(oid);
        KalkanProxy derValue = KalkanAdapter.createDERUTF8String(value);
        KalkanProxy vector = KalkanAdapter.createASN1EncodableVector();

        // Add components to vector
        KalkanProxy taggedOid = KalkanAdapter.createDERTaggedObject(true, 0, derOid);
        vector.invoke(ProxyArg.script("realObject.add(args[0])", taggedOid));
        vector.invoke(ProxyArg.script("realObject.add(args[0])", derValue));

        KalkanProxy otherName = KalkanAdapter.createDERSequence(vector);
        KalkanProxy generalName = KalkanAdapter.createGeneralName(KalkanConstants.GeneralName.otherName, otherName);
        add(generalName);
    }

}
