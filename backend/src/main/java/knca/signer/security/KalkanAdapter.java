package knca.signer.security;

import knca.signer.security.KalkanProxy.ProxyArg;
import knca.signer.security.KalkanProxy.ProxyResult;

import java.security.PublicKey;

/**
 * Static utility adapter for Kalkan cryptographic operations.
 * Provides high-level methods that use ProxyArg and ProxyResult internally.
 */
public class KalkanAdapter {

    // ========== Creation Methods (mirroring KalkanRegistry) ==========

    public static KalkanProxy createAlgorithmIdentifier(Object objectId, Object parameters) {
        return KalkanRegistry.createAlgorithmIdentifier(objectId, parameters);
    }

    public static KalkanProxy createASN1EncodableVector() {
        return KalkanRegistry.createASN1EncodableVector();
    }

    public static KalkanProxy createDERObjectIdentifier(String oid) {
        return KalkanRegistry.createDERObjectIdentifier(oid);
    }

    public static KalkanProxy createDERSequence(Object vector) {
        return KalkanRegistry.createDERSequence(vector);
    }

    public static KalkanProxy createDERInteger(byte[] serNum) {
        return KalkanRegistry.createDERInteger(serNum);
    }

    public static KalkanProxy createDERNull() {
        return KalkanRegistry.createDERNull();
    }

    public static KalkanProxy createDERUTF8String(String value) {
        return KalkanRegistry.createDERUTF8String(value);
    }

    public static KalkanProxy createDERTaggedObject(boolean explicit, int tagNo, Object obj) {
        return KalkanRegistry.createDERTaggedObject(explicit, tagNo, obj);
    }

    public static KalkanProxy createGeneralName(int tag, Object name) {
        return KalkanRegistry.createGeneralName(tag, name);
    }

    public static KalkanProxy createGeneralNames(Object sequence) {
        return KalkanRegistry.createGeneralNames(sequence);
    }

    public static KalkanProxy createX509Name(String name) {
        return KalkanRegistry.createX509Name(name);
    }

    public static KalkanProxy createTime(java.util.Date time) {
        return KalkanRegistry.createTime(time);
    }

    public static KalkanProxy createBasicConstraints(boolean ca) {
        return KalkanRegistry.createBasicConstraints(ca);
    }

    public static KalkanProxy createKeyUsage(int keyUsage) {
        return KalkanRegistry.createKeyUsage(keyUsage);
    }

    public static KalkanProxy createSubjectPublicKeyInfo(Object seq) {
        return KalkanRegistry.createSubjectPublicKeyInfo(seq);
    }

    public static KalkanProxy createV3TBSCertificateGenerator() {
        return KalkanRegistry.createV3TBSCertificateGenerator();
    }

    public static KalkanProxy createX509ExtensionsGenerator() {
        return KalkanRegistry.createX509ExtensionsGenerator();
    }

    public static KalkanProxy createX509V3CertificateGenerator() {
        return KalkanRegistry.createX509V3CertificateGenerator();
    }

    public static KalkanProxy createPEMWriter(java.io.Writer writer) {
        return KalkanRegistry.createPEMWriter(writer);
    }

    // ========== Simplified Operation Methods ==========

    public static void setSerialNumber(KalkanProxy tbsGen, byte[] serialNumber) {
        KalkanProxy derInteger = createDERInteger(serialNumber);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setSerialNumber")
                .paramTypes(null)
                .args(new Object[]{derInteger})
                .build());
    }

    public static void setSignature(KalkanProxy tbsGen, String signatureAlgorithm) {
        KalkanProxy algorithmIdentifier = createAlgorithmIdentifier(createDERObjectIdentifier(signatureAlgorithm), createDERNull());
        tbsGen.invoke(KalkanProxy.ProxyArg.builder()
                .methodName("setSignature")
                .paramTypes(null)
                .args(new Object[]{algorithmIdentifier})
                .build());
    }

    public static void setIssuer(KalkanProxy tbsGen, String issuer) {
        KalkanProxy x509Name = createX509Name(issuer);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setIssuer")
                .paramTypes(null)
                .args(new Object[]{x509Name})
                .build());
    }

    public static void setSubject(KalkanProxy tbsGen, String subject) {
        KalkanProxy x509Name = createX509Name(subject);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setSubject")
                .paramTypes(null)
                .args(new Object[]{x509Name})
                .build());
    }

    public static void setSubjectPublicKeyInfo(KalkanProxy tbsGen, PublicKey userPublicKey) throws Exception {
        KalkanProxy subjPubKeyInfo = KalkanAdapter.createSubjectPublicKeyInfo(userPublicKey);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setSubjectPublicKeyInfo")
                .paramTypes(null)
                .args(new Object[]{subjPubKeyInfo})
                .build());
    }

    public static void addExtension(KalkanProxy extGen, String oid, boolean critical, Object value) {
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        extGen.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, value})
                .build());
    }

    public static void addExtension(KalkanProxy extGen, String oid, boolean critical, boolean booleanValue) {
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        KalkanProxy basicConstraints = createBasicConstraints(booleanValue);
        extGen.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, basicConstraints})
                .build());
    }

    public static void addExtension(KalkanProxy extGen, String oid, boolean critical, int keyUsage) {
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        KalkanProxy keyUsageObj = createKeyUsage(keyUsage);
        extGen.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, keyUsageObj})
                .build());
    }

    public static void addExtension(KalkanProxy extGen, String oid, boolean critical, KalkanProxy extensionValue) {
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        extGen.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, extensionValue})
                .build());
    }

    public static void setExtensions(KalkanProxy tbsGen, Object extensions) {
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setExtensions")
                .paramTypes(null)
                .args(new Object[]{extensions})
                .build());
    }

    public static ProxyResult generateExtensions(KalkanProxy extGen) {
        ProxyResult result = extGen.invoke(ProxyArg.builder()
                .methodName("generate")
                .paramTypes(null)
                .args(null)
                .build());

        return result;
    }

    public static ProxyResult generateTBSCertificate(KalkanProxy tbsGen) {
        ProxyResult result = tbsGen.invoke(ProxyArg.builder()
                .methodName("generateTBSCertificate")
                .paramTypes(null)
                .args(null)
                .build());
        return result;
    }

    // ========== Additional Utility Methods ==========

    public static void addToVector(KalkanProxy vector, Object item) {
        vector.invoke(ProxyArg.builder()
                .methodName("add")
                .paramTypes(null)
                .args(new Object[]{item})
                .build());
    }

    public static void setSignatureAlgorithm(KalkanProxy certGen, String signatureAlgorithm) {
        certGen.invoke(ProxyArg.builder()
                .methodName("setSignatureAlgorithm")
                .paramTypes(null)
                .args(new Object[]{signatureAlgorithm})
                .build());
    }

    public static ProxyResult generateCertificate(KalkanProxy certGen, Object tbsCert, Object signature) {
        ProxyResult result = certGen.invoke(ProxyArg.builder()
                .methodName("generate")
                .paramTypes(null)
                .args(new Object[]{tbsCert, signature})
                .build());
        return result;
    }

    public static void writeObject(KalkanProxy pemWriter, Object obj) {
        pemWriter.invoke(ProxyArg.builder()
                .methodName("writeObject")
                .paramTypes(null)
                .args(new Object[]{obj})
                .build());
    }

    public static void flush(KalkanProxy pemWriter) {
        pemWriter.invoke(ProxyArg.builder()
                .methodName("flush")
                .paramTypes(null)
                .args(null)
                .build());
    }

    // ========== Higher-level convenience methods ==========

    public static KalkanProxy createOtherName(String oid, String value) {
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        KalkanProxy derValue = createDERUTF8String(value);
        KalkanProxy vector = createASN1EncodableVector();
        addToVector(vector, createDERTaggedObject(true, 0, derOid));
        addToVector(vector, derValue);
        return createDERSequence(vector);
    }

    public static void addGeneralNameEmail(KalkanProxy vector, String email) {
        KalkanProxy generalName = createGeneralName(KalkanConstants.GeneralName.rfc822Name, email);
        addToVector(vector, generalName);
    }

    public static void addGeneralNameOtherName(KalkanProxy vector, String oid, String value) {
        KalkanProxy otherName = createOtherName(oid, value);
        KalkanProxy generalName = createGeneralName(KalkanConstants.GeneralName.otherName, otherName);
        addToVector(vector, generalName);
    }

    public static void setStartDate(KalkanProxy tbsGen, java.util.Date startDate) {
        KalkanProxy time = createTime(startDate);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setStartDate")
                .paramTypes(null)
                .args(new Object[]{time})
                .build());
    }

    public static void setEndDate(KalkanProxy tbsGen, java.util.Date endDate) {
        KalkanProxy time = createTime(endDate);
        tbsGen.invoke(ProxyArg.builder()
                .methodName("setEndDate")
                .paramTypes(null)
                .args(new Object[]{time})
                .build());
    }

    public static void addExtendedKeyUsageEmailProtection(KalkanProxy extGen) {
        KalkanProxy eku = createDERSequence(createDERObjectIdentifier(KalkanConstants.KeyPurposeId.id_kp_emailProtection));
        addExtension(extGen, KalkanConstants.X509Extensions.ExtendedKeyUsage, false, eku);
    }

    public static void addSubjectAlternativeName(KalkanProxy extGen, KalkanProxy sanVector) {
        KalkanProxy sanSequence = createDERSequence(sanVector);
        KalkanProxy sanGeneralNames = createGeneralNames(sanSequence);
        addExtension(extGen, KalkanConstants.X509Extensions.SubjectAlternativeName, false, sanGeneralNames);
    }

    // ========== TBS Certificate Utility Methods ==========

    /**
     * Get DER encoded bytes from a TBS certificate object.
     * This encapsulates the reflection call for getting DER encoding.
     */
    public static byte[] getDEREncoded(Object tbsCert) {
        return (byte[]) ReflectionHelper.invokeMethod(ReflectionHelper.unwrapValue(tbsCert), "getDEREncoded", null, null);
    }

    public static KalkanProxy createSubjectPublicKeyInfo(PublicKey publicKey) {
        Object seq = KalkanRegistry.createASN1SequenceFromPublicKey(publicKey);
        return createSubjectPublicKeyInfo(seq);
    }
}
