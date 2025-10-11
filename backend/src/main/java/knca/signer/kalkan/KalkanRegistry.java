package knca.signer.kalkan;

import knca.signer.kalkan.api.PEMWriter;
import knca.signer.kalkan.api.V3TBSCertificateGenerator;
import knca.signer.kalkan.api.X509ExtensionsGenerator;
import knca.signer.kalkan.api.X509V3CertificateGenerator;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;

import java.io.Writer;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class KalkanRegistry {

    private static final ByteBuddy buddy = new ByteBuddy();
    public static final AtomicReference<ClassLoader> CLASS_LOADER = new AtomicReference<>(KalkanRegistry.class.getClassLoader());

    public static Object wrapValue(Object result) {
        if (result == null) return null;
        if (result instanceof KalkanProxy) return result;
        return createProxy(result.getClass(), result);
    }

    private static KalkanProxy createProxy(Class<?> clazz, Object instance) {
        try {
            DynamicType.Unloaded<?> unloaded = buddy
                    .subclass(Object.class)
                    .implement(KalkanProxy.class)
                    .implement(clazz.getInterfaces())
                    .defineField("_instance", Object.class, Opcodes.ACC_PRIVATE)
                    .defineConstructor(Opcodes.ACC_PUBLIC)
                    .withParameters(Object.class)
                    .intercept(MethodCall.invoke(Object.class.getConstructor())
                            .andThen(FieldAccessor.ofField("_instance").setsArgumentAt(0)))
                    .method(ElementMatchers.named("getRealObject"))
                    .intercept(FieldAccessor.ofField("_instance"))
                    .method(ElementMatchers.named("equals"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) ->
                            ((KalkanProxy) p).getRealObject().equals(ReflectionHelper.unwrapValue(a[0]))))
                    .method(ElementMatchers.named("hashCode"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) -> ((KalkanProxy) p).getRealObject().hashCode()))
                    .method(ElementMatchers.named("toString"))
                    .intercept(InvocationHandlerAdapter.of((p, m, a) ->
                            "KalkanProxy[%s]: %s".formatted(((KalkanProxy) p).getRealObject().getClass().getName(), ((KalkanProxy) p).getRealObject())))
                    .method(ElementMatchers.not(ElementMatchers.named("getRealObject")).and(ElementMatchers.not(ElementMatchers.named("invoke")))
                            .and(ElementMatchers.not(ElementMatchers.named("getResult"))).and(ElementMatchers.not(ElementMatchers.named("getResultType")))
                            .and(ElementMatchers.not(ElementMatchers.named("genericValue"))).and(ElementMatchers.not(ElementMatchers.named("equals")))
                            .and(ElementMatchers.not(ElementMatchers.named("hashCode"))).and(ElementMatchers.not(ElementMatchers.named("toString"))))
                    .intercept(InvocationHandlerAdapter.of(new TransparentProxyHandler(instance)))
                    .make();
            Class<?> proxyClass = unloaded.load(CLASS_LOADER.get()).getLoaded();
            return (KalkanProxy) proxyClass.getConstructor(Object.class).newInstance(instance);
        } catch (Exception e) {
            throw new KalkanException("Failed to create proxy for " + clazz.getName(), e);
        }
    }

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

    /**
     * Create a V3TBSCertificateGenerator interface wrapper
     */
    public static V3TBSCertificateGenerator createV3TBSCertificateGenerator() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.asn1.x509.V3TBSCertificateGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a X509ExtensionsGenerator interface wrapper
     */
    public static X509ExtensionsGenerator createX509ExtensionsGenerator() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.asn1.x509.X509ExtensionsGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a X509V3CertificateGenerator interface wrapper
     */
    public static X509V3CertificateGenerator createX509V3CertificateGenerator() {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.x509.X509V3CertificateGenerator", null, null);
        return () -> kalkanProxy;
    }

    /**
     * Create a PEMWriter interface wrapper
     */
    public static PEMWriter createPEMWriter(java.io.Writer writer) {
        KalkanProxy kalkanProxy = create("kz.gov.pki.kalkan.openssl.PEMWriter", new Class[]{Writer.class}, new Object[]{writer});
        return () -> kalkanProxy;
    }

    @SneakyThrows
    public static Object createASN1SequenceFromPublicKey(java.security.PublicKey publicKey) {
        Class<?> asn1ObjectClass = ReflectionHelper.loadKalkanClass("kz.gov.pki.kalkan.asn1.ASN1Object");
        return ReflectionHelper.invokeStaticMethod(asn1ObjectClass, "fromByteArray", asn1ObjectClass,
                new Class[]{byte[].class}, new Object[]{publicKey.getEncoded()});
    }

    private static KalkanProxy create(String className, Class<?>[] paramTypes, Object[] args) {
        try {
            Class<?> realClass = ReflectionHelper.loadKalkanClass(className);
            Object instance = ReflectionHelper.newInstance(realClass, paramTypes, args);
            return createProxy(realClass, instance);
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
                if (log.isTraceEnabled()) {
                    log.trace("Method '{}' returned {}", method.getName(), result);
                }
                return wrapValue(result);
            } catch (Throwable e) {
                log.trace("Method '{}' threw exception: {}", method.getName(), e.getMessage());
                throw Objects.nonNull(e.getCause()) ? e.getCause() : e;
            }
        }

    }

}
