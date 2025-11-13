package knca.signer.kalkan;

import knca.signer.kalkan.api.*;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.mvel2.MVEL;

import java.io.Serializable;
import java.io.Writer;
import java.lang.reflect.Array;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KalkanRegistry provides high-performance proxy creation and method dispatching
 * for the Kazakhstani NCA Kalkan cryptography library using MVEL expression evaluation.
 * <p>
 * Key Features:
 * - MVEL-powered method dispatching for optimal performance
 * - Script caching for frequently used operations
 * - Simple wrapper-based proxies (no dynamic bytecode generation)
 * - Seamless integration avoiding commercial licensing restrictions
 * <p>
 * Performance Benefits:
 * - Eliminates Java reflection overhead through compiled MVEL expressions
 * - Startup time improvement by removing ByteBuddy bytecode manipulation
 * - Memory-efficient lightweight proxy implementation
 */
@Slf4j
public class KalkanRegistry {

    // MVEL script cache for performance
    private static final Map<String, Serializable> SCRIPT_CACHE = new ConcurrentHashMap<>();

    public static Object wrapValue(Object result) {
        if (result == null) return null;
        if (result instanceof KalkanProxy) return result;
        return createProxy(result.getClass(), result);
    }

    /**
     * Load the real KalkanProvider instance using reflection and register it
     */
    public static Provider loadRealKalkanProvider() throws Exception {
        try {
            Class<?> pc = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.jce.provider.KalkanProvider");
            Object rp = ReflectionHelper.newInstance(pc);
            Security.addProvider((Provider) rp);
            return (Provider) rp;
        } catch (Exception e) {
            throw new KalkanException("Failed to load KalkanProvider", e);
        }
    }

    private static KalkanProxy createProxy(Class<?> clazz, Object instance) {
        try {
            return new MVELKalkanProxy(instance);
        } catch (Exception e) {
            throw new KalkanException("Failed to create proxy for " + clazz.getName(), e);
        }
    }

    public KalkanProxy createAlgorithmIdentifier(Object objectId, Object parameters) {
        try {
            return create("kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier",
                    new Class[]{ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DERObjectIdentifier"),
                            ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodable")},
                    new Object[]{ReflectionHelper.unwrapValue(objectId), ReflectionHelper.unwrapValue(parameters)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load classes for AlgorithmIdentifier", e);
        }
    }

    public KalkanProxy createASN1EncodableVector() {
        try {
            return create("kz.gov.pki.kalkan.asn1.DEREncodableVector", null, null);
        } catch (Exception e) {
            // Fallback to ASN1EncodableVector
            return create("kz.gov.pki.kalkan.asn1.ASN1EncodableVector", null, null);
        }
    }

    public KalkanProxy createKalkanProvider() {
        return create("kz.gov.pki.kalkan.jce.provider.KalkanProvider", null, null);
    }

    public KalkanProxy createDERObjectIdentifier(String oid) {
        return create("kz.gov.pki.kalkan.asn1.DERObjectIdentifier", new Class[]{String.class}, new Object[]{oid});
    }

    public KalkanProxy createDERSequence(Object vector) {
        try {
            Object unwrapped = ReflectionHelper.unwrapValue(vector);
            Class<?> derEncodableVectorClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodableVector");
            Class<?> asn1EncodableClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Encodable");

            if (ReflectionHelper.is(derEncodableVectorClass, unwrapped)) {
                return create("kz.gov.pki.kalkan.asn1.DERSequence", new Class[]{derEncodableVectorClass}, new Object[]{unwrapped});
            } else if (ReflectionHelper.is(asn1EncodableClass, unwrapped)) {
                Object instance = Array.newInstance(asn1EncodableClass, 1);
                ((Object[]) instance)[0] = unwrapped;
                return create("kz.gov.pki.kalkan.asn1.DERSequence", new Class[]{instance.getClass()}, new Object[]{instance});
            } else {
                return create("kz.gov.pki.kalkan.asn1.DERSequence", null, null);
            }
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load classes for DERSequence", e);
        }
    }

    public KalkanProxy createDERInteger(byte[] serNum) {
        return create("kz.gov.pki.kalkan.asn1.DERInteger", new Class[]{byte[].class}, new Object[]{serNum});
    }

    public KalkanProxy createDERNull() {
        return create("kz.gov.pki.kalkan.asn1.DERNull", null, null);
    }

    public KalkanProxy createDERUTF8String(String value) {
        return create("kz.gov.pki.kalkan.asn1.DERUTF8String", new Class[]{String.class}, new Object[]{value});
    }

    public KalkanProxy createDERTaggedObject(boolean explicit, int tagNo, Object obj) {
        try {
            return create("kz.gov.pki.kalkan.asn1.DERTaggedObject",
                    new Class[]{boolean.class, int.class, ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodable")},
                    new Object[]{explicit, tagNo, ReflectionHelper.unwrapValue(obj)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load DEREncodable class", e);
        }
    }

    public KalkanProxy createGeneralName(int tag, Object name) {
        Object unwrapped = ReflectionHelper.unwrapValue(name);
        if (unwrapped instanceof String) {
            return create("kz.gov.pki.kalkan.asn1.x509.GeneralName", new Class[]{int.class, String.class}, new Object[]{tag, unwrapped});
        } else {
            try {
                Class<?> asn1EncodableClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Encodable");
                return create("kz.gov.pki.kalkan.asn1.x509.GeneralName",
                        new Class[]{int.class, asn1EncodableClass}, new Object[]{tag, unwrapped});
            } catch (ClassNotFoundException e) {
                throw new KalkanException("Failed to load ASN1Encodable class", e);
            }
        }
    }

    public KalkanProxy createGeneralNames(Object sequence) {
        try {
            Class<?> asn1SequenceClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Sequence");
            return create("kz.gov.pki.kalkan.asn1.x509.GeneralNames",
                    new Class[]{asn1SequenceClass}, new Object[]{ReflectionHelper.unwrapValue(sequence)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load ASN1Sequence class", e);
        }
    }

    public KalkanProxy createX509Name(String name) {
        return create("kz.gov.pki.kalkan.asn1.x509.X509Name", new Class[]{String.class}, new Object[]{name});
    }

    public KalkanProxy createTime(Date time) {
        return create("kz.gov.pki.kalkan.asn1.x509.Time", new Class[]{Date.class}, new Object[]{time});
    }

    public KalkanProxy createBasicConstraints(boolean ca) {
        return create("kz.gov.pki.kalkan.asn1.x509.BasicConstraints", new Class[]{boolean.class}, new Object[]{ca});
    }

    public KalkanProxy createKeyUsage(int keyUsage) {
        return create("kz.gov.pki.kalkan.asn1.x509.KeyUsage", new Class[]{int.class}, new Object[]{keyUsage});
    }

    public KalkanProxy createSubjectPublicKeyInfo(Object seq) {
        try {
            Class<?> asn1SequenceClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Sequence");
            return create("kz.gov.pki.kalkan.asn1.x509.SubjectPublicKeyInfo",
                    new Class[]{asn1SequenceClass}, new Object[]{ReflectionHelper.unwrapValue(seq)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load ASN1Sequence class", e);
        }
    }

    /**
     * Create a X509ExtensionsGenerator interface wrapper
     */
    public X509ExtensionsGenerator createX509ExtensionsGenerator() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.asn1.x509.X509ExtensionsGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a X509V3CertificateGenerator interface wrapper
     */
    public X509V3CertificateGenerator createX509V3CertificateGenerator() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.x509.X509V3CertificateGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a ASN1EncodableVector interface wrapper
     */
    public ASN1EncodableVector createASN1EncodableVectorWrapper() {
        KalkanProxy kalkanProxy = createASN1EncodableVector();
        return () -> kalkanProxy;
    }

    /**
     * Create a PEMWriter interface wrapper
     */
    public PEMWriter createPEMWriter(Writer writer) {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.openssl.PEMWriter", new Class[]{Writer.class}, new Object[]{writer});
        return () -> kalkanProxy;
    }

    /**
     * Create a TBSCertificateManager interface wrapper
     */
    public TBSCertificateManager createTBSCertificateManager() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.asn1.x509.V3TBSCertificateGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a Kalkan-compatible JKS keystore using direct SPI instantiation
     * This ensures compatibility with real Kalkan applications by using JavaKeyStore.JKS directly
     */
    public KalkanProxy createKalkanJKSKeystore() {
        try {
            // Direct instantiation of JavaKeyStore.JKS (bypasses JVM KeyStore factory)
            Class<?> jksClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.jce.provider.JavaKeyStore$JKS");
            Object jksInstance = ReflectionHelper.newInstance(jksClass);
            return createProxy(jksClass, jksInstance);
        } catch (Exception e) {
            throw new KalkanException("Failed to create Kalkan JKS keystore", e);
        }
    }

    /**
     * Create a Kalkan-compatible PKCS12 keystore using direct SPI instantiation
     * This ensures compatibility with real Kalkan applications by using JDKPKCS12KeyStore.BCPKCS12KeyStore
     */
    public KalkanProxy createKalkanPKCS12Keystore() {
        try {
            // Direct instantiation of JDKPKCS12KeyStore.BCPKCS12KeyStore (kalkan-specific implementation)
            Class<?> pkcs12Class = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
            Object pkcs12Instance = ReflectionHelper.newInstance(pkcs12Class);
            return createProxy(pkcs12Class, pkcs12Instance);
        } catch (Exception e) {
            throw new KalkanException("Failed to create Kalkan PKCS12 keystore", e);
        }
    }

    @SneakyThrows
    public Object createASN1SequenceFromPublicKey(PublicKey publicKey) {
        Class<?> asn1ObjectClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Object");
        return ReflectionHelper.invokeStaticMethod(asn1ObjectClass, "fromByteArray", asn1ObjectClass,
                new Class[]{byte[].class}, new Object[]{publicKey.getEncoded()});
    }

    private KalkanProxy create(String className, Class<?>[] paramTypes, Object[] args) {
        try {
            Class<?> realClass = ReflectionHelper.loadKalkanClass(className);
            Object instance = ReflectionHelper.newInstance(realClass, paramTypes, args);
            return createProxy(realClass, instance);
        } catch (Exception e) {
            throw new KalkanException("Failed to create proxy for " + className, e);
        }
    }

    /**
     * Simple wrapper implementation that uses MVEL for method dispatching
     */
    @Value
    @RequiredArgsConstructor
    private static class MVELKalkanProxy implements KalkanProxy {

        Object realObject;

        @Override
        public KalkanProxy invoke(ProxyArg arg) {
            try {
                Object result;

                // Use MVEL script execution if provided (optimized path)
                if (arg.getScript() != null && !arg.getScript().isEmpty()) {
                    // Create MVEL context with variables
                    var context = new HashMap<>();
                    context.put("realObject", getRealObject());

                    // Unwrap proxy arguments before passing to MVEL
                    var unwrappedArgs = arg.getArgs() != null ? arg.getArgs() : new Object[0];
                    for (int i = 0; i < unwrappedArgs.length; i++) {
                        unwrappedArgs[i] = ReflectionHelper.unwrapValue(unwrappedArgs[i]);
                    }
                    context.put("args", unwrappedArgs);

                    // Cache compiled expressions for performance
                    String scriptKey = arg.getScript();
                    var compiled = SCRIPT_CACHE.computeIfAbsent(scriptKey, s -> MVEL.compileExpression(arg.getScript()));

                    // Execute the MVEL script
                    result = MVEL.executeExpression(compiled, context);
                } else {
                    // Fallback to reflection
                    result = ReflectionHelper.invokeMethod(getRealObject(), arg.getMethodName(), arg.getParamTypes(), arg.getArgs());
                }

                return (KalkanProxy) wrapValue(result);
            } catch (Exception e) {
                throw new KalkanException("Invoke failed", e);
            }
        }

        @Override
        public String toString() {
            return "KalkanProxy[%s]: %s".formatted(getRealObject().getClass().getName(), getRealObject());
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) return false;
            if (this == obj) return true;
            if (obj instanceof KalkanProxy) return Objects.equals(getRealObject(), ReflectionHelper.unwrapValue(obj));
            return Objects.equals(getRealObject(), obj);
        }

        @Override
        public int hashCode() {
            return getRealObject().hashCode();
        }
    }

}
