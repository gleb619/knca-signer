package knca.signer.security;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.matcher.ElementMatchers;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.util.Date;
import java.util.Objects;

@Slf4j
public class KalkanRegistry {

    private static final ByteBuddy buddy = new ByteBuddy();

    public static KalkanProxy createAlgorithmIdentifier(Object objectId, Object parameters) {
        try {
            return create("kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier",
                    new Class[]{ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DERObjectIdentifier"),
                            ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodable")},
                    new Object[]{ReflectionHelper.unwrapValue(objectId), ReflectionHelper.unwrapValue(parameters)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load classes for AlgorithmIdentifier", e);
        }
    }

    public static KalkanProxy createASN1EncodableVector() {
        try {
            return create("kz.gov.pki.kalkan.asn1.DEREncodableVector", null, null);
        } catch (Exception e) {
            // Fallback to ASN1EncodableVector
            return create("kz.gov.pki.kalkan.asn1.ASN1EncodableVector", null, null);
        }
    }

    /**
     * Load the real KalkanProvider instance using reflection and register it
     */
    public static java.security.Provider loadRealKalkanProvider() throws Exception {
        try {
            Class<?> pc = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.jce.provider.KalkanProvider");
            Object rp = ReflectionHelper.newInstance(pc);
            java.security.Security.addProvider((java.security.Provider) rp);
            return (java.security.Provider) rp;
        } catch (Exception e) {
            throw new KalkanException("Failed to load KalkanProvider", e);
        }
    }

    public static KalkanProxy createKalkanProvider() {
        return create("kz.gov.pki.kalkan.jce.provider.KalkanProvider", null, null);
    }

    public static KalkanProxy createDERObjectIdentifier(String oid) {
        return create("kz.gov.pki.kalkan.asn1.DERObjectIdentifier", new Class[]{String.class}, new Object[]{oid});
    }

    public static KalkanProxy createDERSequence(Object vector) {
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

    public static KalkanProxy createDERInteger(byte[] serNum) {
        return create("kz.gov.pki.kalkan.asn1.DERInteger", new Class[]{byte[].class}, new Object[]{serNum});
    }

    public static KalkanProxy createDERNull() {
        return create("kz.gov.pki.kalkan.asn1.DERNull", null, null);
    }

    public static KalkanProxy createDERUTF8String(String value) {
        return create("kz.gov.pki.kalkan.asn1.DERUTF8String", new Class[]{String.class}, new Object[]{value});
    }

    public static KalkanProxy createDERTaggedObject(boolean explicit, int tagNo, Object obj) {
        try {
            return create("kz.gov.pki.kalkan.asn1.DERTaggedObject",
                    new Class[]{boolean.class, int.class, ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodable")},
                    new Object[]{explicit, tagNo, ReflectionHelper.unwrapValue(obj)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load DEREncodable class", e);
        }
    }

    public static KalkanProxy createGeneralName(int tag, Object name) {
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

    public static KalkanProxy createGeneralNames(Object sequence) {
        try {
            Class<?> asn1SequenceClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Sequence");
            return create("kz.gov.pki.kalkan.asn1.x509.GeneralNames",
                    new Class[]{asn1SequenceClass}, new Object[]{ReflectionHelper.unwrapValue(sequence)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load ASN1Sequence class", e);
        }
    }

    public static KalkanProxy createX509Name(String name) {
        return create("kz.gov.pki.kalkan.asn1.x509.X509Name", new Class[]{String.class}, new Object[]{name});
    }

    public static KalkanProxy createTime(Date time) {
        return create("kz.gov.pki.kalkan.asn1.x509.Time", new Class[]{Date.class}, new Object[]{time});
    }

    public static KalkanProxy createBasicConstraints(boolean ca) {
        return create("kz.gov.pki.kalkan.asn1.x509.BasicConstraints", new Class[]{boolean.class}, new Object[]{ca});
    }

    public static KalkanProxy createKeyUsage(int keyUsage) {
        return create("kz.gov.pki.kalkan.asn1.x509.KeyUsage", new Class[]{int.class}, new Object[]{keyUsage});
    }

    public static KalkanProxy createSubjectPublicKeyInfo(Object seq) {
        try {
            Class<?> asn1SequenceClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Sequence");
            return create("kz.gov.pki.kalkan.asn1.x509.SubjectPublicKeyInfo",
                    new Class[]{asn1SequenceClass}, new Object[]{ReflectionHelper.unwrapValue(seq)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load ASN1Sequence class", e);
        }
    }

    public static KalkanProxy createV3TBSCertificateGenerator() {
        return create("kz.gov.pki.kalkan.asn1.x509.V3TBSCertificateGenerator", null, null);
    }

    public static KalkanProxy createX509ExtensionsGenerator() {
        return create("kz.gov.pki.kalkan.asn1.x509.X509ExtensionsGenerator", null, null);
    }

    public static KalkanProxy createX509V3CertificateGenerator() {
        return create("kz.gov.pki.kalkan.x509.X509V3CertificateGenerator", null, null);
    }

    public static KalkanProxy createPEMWriter(java.io.Writer writer) {
        return create("kz.gov.pki.kalkan.openssl.PEMWriter", new Class[]{java.io.Writer.class}, new Object[]{writer});
    }

    @SneakyThrows
    public static Object createASN1SequenceFromPublicKey(java.security.PublicKey publicKey) {
        Class<?> asn1ObjectClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Object");
        return ReflectionHelper.invokeStaticMethod(asn1ObjectClass, "fromByteArray", asn1ObjectClass,
                new Class[]{byte[].class}, new Object[]{publicKey.getEncoded()});
    }

    /**
     * Create ASN.1 parser for certificate extensions
     */
    public static KalkanProxy createASN1InputStream(byte[] data) {
        return create("kz.gov.pki.kalkan.asn1.ASN1InputStream", new Class[]{byte[].class}, new Object[]{data});
    }

    /**
     * Create X509Extension wrapper
     */
    public static KalkanProxy createX509Extension(Object oid, Object critical, Object value) {
        try {
            return create("kz.gov.pki.kalkan.asn1.x509.X509Extension",
                    new Class[]{ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DERObjectIdentifier"),
                            boolean.class, ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1OctetString")},
                    new Object[]{ReflectionHelper.unwrapValue(oid), critical, ReflectionHelper.unwrapValue(value)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load X509Extension classes", e);
        }
    }

    /**
     * Create OtherName for SAN entries
     */
    public static KalkanProxy createOtherName(Object typeId, Object value) {
        try {
            return create("kz.gov.pki.kalkan.asn1.x509.qualified.OtherName",
                    new Class[]{ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DERObjectIdentifier"),
                            ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.DEREncodable")},
                    new Object[]{ReflectionHelper.unwrapValue(typeId), ReflectionHelper.unwrapValue(value)});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load OtherName classes", e);
        }
    }

    /**
     * Create Extensions object for certificate parsing
     */
    public static KalkanProxy createExtensions(Object... extensions) {
        try {
            Class<?> extensionClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.x509.X509Extension");
            return create("kz.gov.pki.kalkan.asn1.x509.Extensions",
                    new Class[]{extensionClass.getClass()}, new Object[]{extensions});
        } catch (ClassNotFoundException e) {
            throw new KalkanException("Failed to load Extensions classes", e);
        }
    }

    /**
     * Create a generic proxy for objects that need to be wrapped
     */
    public static KalkanProxy createObjectProxy(Class<?> clazz) {
        try {
            return create(clazz.getName(), null, null);
        } catch (Exception e) {
            throw new KalkanException("Failed to create proxy for " + clazz.getName(), e);
        }
    }

    private static KalkanProxy create(String className, Class<?>[] paramTypes, Object[] args) {
        try {
            Class<?> realClass = ReflectionHelper.loadKalkanClass(className);
            Object instance = ReflectionHelper.newInstance(realClass, paramTypes, args);

            DynamicType.Unloaded<?> unloaded = buddy
                    .subclass(Object.class)
                    .implement(KalkanProxy.class)
                    .implement(realClass.getInterfaces())
                    .method(ElementMatchers.named("getRealObject"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) -> instance))
                    .method(ElementMatchers.named("equals"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) ->
                            ((KalkanProxy) p).getRealObject().equals(ReflectionHelper.unwrapValue(a[0]))))
                    .method(ElementMatchers.named("hashCode"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) -> ((KalkanProxy) p).getRealObject().hashCode()))
                    .method(ElementMatchers.named("toString"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) ->
                            "KalkanProxy[%s]: %s".formatted(((KalkanProxy) p).getRealObject().getClass().getName(), ((KalkanProxy) p).getRealObject())))
                    .method(ElementMatchers.not(ElementMatchers.named("getRealObject")).and(ElementMatchers.not(ElementMatchers.named("invoke")))
                            .and(ElementMatchers.not(ElementMatchers.named("equals"))).and(ElementMatchers.not(ElementMatchers.named("hashCode")))
                            .and(ElementMatchers.not(ElementMatchers.named("toString"))))
                    .intercept(InvocationHandlerAdapter.of(new TransparentProxyHandler(instance)))
                    .make();

            Class<?> proxyClass = unloaded.load(KalkanRegistry.class.getClassLoader()).getLoaded();
            return (KalkanProxy) proxyClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new KalkanException("Failed to create proxy for " + className, e);
        }
    }

    private static class TransparentProxyHandler implements InvocationHandler {

        private final Object target;

        TransparentProxyHandler(Object target) {
            this.target = target;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            // Delegate all method calls to the real object, unwrapping proxy args
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    args[i] = ReflectionHelper.unwrapValue(args[i]);
                }
            }
            try {
                log.trace("Invoking method '{}' on {} with {} args", method.getName(), target.getClass().getSimpleName(), args != null ? args.length : 0);
                Object result = method.invoke(target, args);
                log.trace("Method '{}' returned successfully", method.getName());
                return ReflectionHelper.unwrapValue(result);
            } catch (Throwable e) {
                log.trace("Method '{}' threw exception: {}", method.getName(), e.getMessage());
                throw Objects.nonNull(e.getCause()) ? e.getCause() : e;
            }
        }

    }

}
