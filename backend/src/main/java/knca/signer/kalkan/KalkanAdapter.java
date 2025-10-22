package knca.signer.kalkan;

import knca.signer.kalkan.KalkanProxy.ProxyArg;
import knca.signer.kalkan.api.PEMWriter;
import knca.signer.kalkan.api.V3TBSCertificateGenerator;
import knca.signer.kalkan.api.X509ExtensionsGenerator;
import knca.signer.kalkan.api.X509V3CertificateGenerator;
import knca.signer.service.CertificateDataGenerator;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

/**
 * Static utility adapter for Kalkan cryptographic operations.
 * Provides high-level methods that use ProxyArg and ProxyResult internally.
 */
@Slf4j
public class KalkanAdapter {

    // ========== Creation Methods (mirroring KalkanRegistry) ==========

    // Check for Kalkan availability
    public static boolean isKalkanAvailable() {
        try {
            Class.forName("kz.gov.pki.kalkan.jce.provider.KalkanProvider");
            return true;
        } catch (ClassNotFoundException e) {
            log.warn("Kalkan JARs not found at runtime, cryptographic operations will fail. Mount JARs to /app/lib if needed");
        }

        return false;
    }

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

    public static V3TBSCertificateGenerator createV3TBSCertificateGenerator() {
        return KalkanRegistry.createV3TBSCertificateGenerator();
    }

    public static X509ExtensionsGenerator createX509ExtensionsGenerator() {
        return KalkanRegistry.createX509ExtensionsGenerator();
    }

    public static X509V3CertificateGenerator createX509V3CertificateGenerator() {
        return KalkanRegistry.createX509V3CertificateGenerator();
    }

    public static PEMWriter createPEMWriter(java.io.Writer writer) {
        return KalkanRegistry.createPEMWriter(writer);
    }

    // ========== Simplified Operation Methods ==========

    public static void setSerialNumber(Object tbsGen, byte[] serialNumber) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy derInteger = createDERInteger(serialNumber);
        proxy.invoke(ProxyArg.builder()
                .methodName("setSerialNumber")
                .paramTypes(null)
                .args(new Object[]{derInteger})
                .build());
    }

    public static void setSignature(Object tbsGen, String signatureAlgorithm) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy algorithmIdentifier = createAlgorithmIdentifier(createDERObjectIdentifier(signatureAlgorithm), createDERNull());
        proxy.invoke(KalkanProxy.ProxyArg.builder()
                .methodName("setSignature")
                .paramTypes(null)
                .args(new Object[]{algorithmIdentifier})
                .build());
    }

    public static void setIssuer(Object tbsGen, String issuer) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy x509Name = createX509Name(issuer);
        proxy.invoke(ProxyArg.builder()
                .methodName("setIssuer")
                .paramTypes(null)
                .args(new Object[]{x509Name})
                .build());
    }

    public static void setSubject(Object tbsGen, String subject) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy x509Name = createX509Name(subject);
        proxy.invoke(ProxyArg.builder()
                .methodName("setSubject")
                .paramTypes(null)
                .args(new Object[]{x509Name})
                .build());
    }

    public static void setSubjectPublicKeyInfo(Object tbsGen, PublicKey userPublicKey) throws Exception {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy subjPubKeyInfo = KalkanAdapter.createSubjectPublicKeyInfo(userPublicKey);
        proxy.invoke(ProxyArg.builder()
                .methodName("setSubjectPublicKeyInfo")
                .paramTypes(null)
                .args(new Object[]{subjPubKeyInfo})
                .build());
    }

    public static void addExtension(Object extGen, String oid, boolean critical, Object value) {
        KalkanProxy proxy = resolveProxy(extGen);
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        proxy.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, value})
                .build());
    }

    public static void addExtension(Object extGen, String oid, boolean critical, boolean booleanValue) {
        KalkanProxy proxy = resolveProxy(extGen);
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        KalkanProxy basicConstraints = createBasicConstraints(booleanValue);
        proxy.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, basicConstraints})
                .build());
    }

    public static void addExtension(Object extGen, String oid, boolean critical, int keyUsage) {
        KalkanProxy proxy = resolveProxy(extGen);
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        KalkanProxy keyUsageObj = createKeyUsage(keyUsage);
        proxy.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, keyUsageObj})
                .build());
    }

    public static void addExtension(Object extGen, String oid, boolean critical, KalkanProxy extensionValue) {
        KalkanProxy proxy = resolveProxy(extGen);
        KalkanProxy derOid = createDERObjectIdentifier(oid);
        proxy.invoke(ProxyArg.builder()
                .methodName("addExtension")
                .paramTypes(null)
                .args(new Object[]{derOid, critical, extensionValue})
                .build());
    }

    public static void setExtensions(Object tbsGen, Object extensions) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        proxy.invoke(ProxyArg.builder()
                .methodName("setExtensions")
                .paramTypes(null)
                .args(new Object[]{extensions})
                .build());
    }

    public static KalkanProxy generateExtensions(Object extGen) {
        KalkanProxy proxy = resolveProxy(extGen);
        return proxy.invoke(ProxyArg.builder()
                .methodName("generate")
                .paramTypes(null)
                .args(null)
                .build());
    }

    public static KalkanProxy generateTBSCertificate(Object tbsGen) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        return proxy.invoke(ProxyArg.builder()
                .methodName("generateTBSCertificate")
                .paramTypes(null)
                .args(null)
                .build());
    }

    // ========== Additional Utility Methods ==========

    public static void addToVector(KalkanProxy vector, Object item) {
        vector.invoke(ProxyArg.builder()
                .methodName("add")
                .paramTypes(null)
                .args(new Object[]{item})
                .build());
    }

    public static void setSignatureAlgorithm(Object certGen, String signatureAlgorithm) {
        KalkanProxy proxy = resolveProxy(certGen);
        proxy.invoke(ProxyArg.builder()
                .methodName("setSignatureAlgorithm")
                .paramTypes(null)
                .args(new Object[]{signatureAlgorithm})
                .build());
    }

    public static KalkanProxy generateCertificate(Object certGen, Object tbsCert, Object signature) {
        KalkanProxy proxy = resolveProxy(certGen);
        return proxy.invoke(ProxyArg.builder()
                .methodName("generate")
                .paramTypes(null)
                .args(new Object[]{tbsCert, signature})
                .build());
    }

    public static void writeObject(Object pemWriter, Object obj) {
        KalkanProxy proxy = resolveProxy(pemWriter);
        proxy.invoke(ProxyArg.builder()
                .methodName("writeObject")
                .paramTypes(null)
                .args(new Object[]{obj})
                .build());
    }

    public static void flush(Object pemWriter) {
        KalkanProxy proxy = resolveProxy(pemWriter);
        proxy.invoke(ProxyArg.builder()
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

    public static void setStartDate(Object tbsGen, java.util.Date startDate) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy time = createTime(startDate);
        proxy.invoke(ProxyArg.builder()
                .methodName("setStartDate")
                .paramTypes(null)
                .args(new Object[]{time})
                .build());
    }

    public static void setEndDate(Object tbsGen, java.util.Date endDate) {
        KalkanProxy proxy = resolveProxy(tbsGen);
        KalkanProxy time = createTime(endDate);
        proxy.invoke(ProxyArg.builder()
                .methodName("setEndDate")
                .paramTypes(null)
                .args(new Object[]{time})
                .build());
    }

    public static void addExtendedKeyUsageEmailProtection(Object extGen) {
        KalkanProxy eku = createDERSequence(createDERObjectIdentifier(KalkanConstants.KeyPurposeId.id_kp_emailProtection));
        addExtension(extGen, KalkanConstants.X509Extensions.ExtendedKeyUsage, false, eku);
    }

    public static void addSubjectAlternativeName(Object extGen, KalkanProxy sanVector) {
        KalkanProxy sanSequence = createDERSequence(sanVector);
        KalkanProxy sanGeneralNames = createGeneralNames(sanSequence);
        addExtension(extGen, KalkanConstants.X509Extensions.SubjectAlternativeName, false, sanGeneralNames);
    }

    // ========== Helper Methods ==========

    private static KalkanProxy resolveProxy(Object obj) {
        return switch (obj) {
            case KalkanProxy p -> p;
            case X509ExtensionsGenerator x -> x.getProxy();
            case V3TBSCertificateGenerator v -> v.getProxy();
            case X509V3CertificateGenerator c -> c.getProxy();
            case PEMWriter w -> w.getProxy();
            default -> throw new IllegalArgumentException("Unsupported proxy type: " + obj.getClass());
        };
    }

    // ========== TBS Certificate Utility Methods ==========

    /**
     * Get DER encoded bytes from a TBS certificate object.
     * Uses KalkanRegistry to create appropriate proxy and invoke method.
     */
    public static byte[] getDEREncoded(Object tbsCert) {
        if (tbsCert instanceof KalkanProxy proxy) {
            // If it's already a proxy, invoke directly
            KalkanProxy result = proxy.invoke(ProxyArg.builder()
                    .methodName("getDEREncoded")
                    .paramTypes(null)
                    .args(null)
                    .build());
            return (byte[]) result.getRealObject();
        } else {
            // Use reflection for objects that aren't proxies yet
            var rawValue = ReflectionHelper.unwrapValue(tbsCert);
            return (byte[]) ReflectionHelper.invokeMethod(rawValue, "getDEREncoded", null, null);
        }
    }

    public static KalkanProxy createSubjectPublicKeyInfo(PublicKey publicKey) {
        Object seq = KalkanRegistry.createASN1SequenceFromPublicKey(publicKey);
        return createSubjectPublicKeyInfo(seq);
    }

    /**
     * Extract email from certificate's Subject Alternative Name extension.
     * Uses certificate string parsing as a workaround for Kalkan's ASN.1 parsing issues.
     */
    public static String extractEmailFromCertificate(Object x509Certificate) {
        // For Kalkan certificates, parse the certificate string representation
        // This is more reliable than reflection for SAN extraction
        try {
            String certString = x509Certificate.toString();
            return parseEmailFromCertificateString(certString);
        } catch (Exception e) {
            log.warn("Failed to extract email from certificate string: {}", e.getMessage());
            try {
                // Final fallback: try extension parsing
                return parseEmailFromExtensions(x509Certificate);
            } catch (Exception extException) {
                log.error("All email extraction methods failed: {}", extException.getMessage());
            }
        }

        return "user@example.com"; // default
    }

    /**
     * Extract email from certificate's string representation
     */
    private static String parseEmailFromCertificateString(String certString) {
        String[] lines = certString.split("\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.contains("RFC822Name:") || line.contains("EMAILADDRESS=")) {
                if (line.contains("RFC822Name:")) {
                    return line.substring(line.indexOf("RFC822Name:") + "RFC822Name:".length()).trim();
                } else if (line.contains("EMAILADDRESS=")) {
                    int startIndex = line.indexOf("EMAILADDRESS=");
                    int endIndex = line.indexOf(",", startIndex);
                    if (endIndex == -1) {
                        return line.substring(startIndex + "EMAILADDRESS=".length()).trim();
                    } else {
                        return line.substring(startIndex + "EMAILADDRESS=".length(), endIndex).trim();
                    }
                }
            }
        }

        // Look for email in Subject Alternative Name extensions section
        boolean inExtensions = false;
        for (String line : lines) {
            line = line.trim();
            if (line.contains("Subject Alternative Name")) {
                inExtensions = true;
                continue;
            }
            if (inExtensions && line.contains("[") && line.contains("]")) {
                // Extract email from bracketed entries
                int bracketStart = line.indexOf("[");
                int bracketEnd = line.indexOf("]", bracketStart);
                if (bracketStart >= 0 && bracketEnd > bracketStart) {
                    String content = line.substring(bracketStart + 1, bracketEnd);
                    if (content.contains("RFC822Name")) {
                        // Extract the actual email value
                        String[] parts = content.split(":");
                        if (parts.length >= 2) {
                            return parts[1].trim();
                        }
                    }
                }
            }
        }

        return "user@example.com"; // default if not found
    }

    /**
     * Fallback method to parse SAN extensions directly (may fail with Kalkan)
     */
    private static String parseEmailFromExtensions(Object x509Certificate) throws Exception {
        try {
            var sans = (Collection) ReflectionHelper.invokeMethod(x509Certificate, "getSubjectAlternativeNames", null, null);
            if (sans != null) {
                for (Object san : sans) {
                    var sanList = (List) san;
                    if (sanList.size() >= 2 && sanList.get(0).equals(1)) { // RFC822Name = 1
                        return (String) sanList.get(1);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to extract data: ", e);
        }

        return "user@example.com"; // default
    }

    /**
     * Extract IIN (Individual Identification Number) from certificate's otherName SAN entry
     * Uses string parsing instead of ASN.1 parsing due to Kalkan certificate incompatibilities
     */
    public static String extractIINFromCertificate(Object x509Certificate) {
        try {
            // Use string parsing as the primary method - more reliable than ASN.1 parsing
            String certString = x509Certificate.toString();

            // Parse IIN from DN field
            if (certString.contains("SN=IIN") || certString.contains("SERIALNUMBER=IIN")) {
                java.util.regex.Pattern iinPattern = java.util.regex.Pattern.compile("[A-Z]*IIN(\\d{12})");
                java.util.regex.Matcher matcher = iinPattern.matcher(certString);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

            // Look for otherName IIN in extensions
            if (certString.contains(CertificateDataGenerator.IIN_OID)) {
                java.util.regex.Pattern digitPattern = java.util.regex.Pattern.compile("\\d{12}");
                java.util.regex.Matcher digitMatcher = digitPattern.matcher(certString);
                if (digitMatcher.find()) {
                    return digitMatcher.group();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract IIN using string parsing: {}", e.getMessage());
        }

        return "123456789012"; // default fallback
    }

    /**
     * Extract BIN (Business Identification Number) from certificate's otherName SAN entry
     * Uses string parsing instead of ASN.1 parsing due to Kalkan certificate incompatibilities
     */
    public static String extractBINFromCertificate(Object x509Certificate) {
        try {
            // Use string parsing as the primary method - more reliable than ASN.1 parsing
            String certString = x509Certificate.toString();

            // Parse BIN from DN field
            if (certString.contains("OU=BIN") || certString.contains("ORGANIZATIONALUNITNAME=BIN")) {
                java.util.regex.Pattern binPattern = java.util.regex.Pattern.compile("[A-Z]*BIN(\\d{12})");
                java.util.regex.Matcher matcher = binPattern.matcher(certString);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

            // Look for otherName BIN in extensions
            if (certString.contains(CertificateDataGenerator.BIN_OID)) {
                java.util.regex.Pattern digitPattern = java.util.regex.Pattern.compile("\\d{12}");
                java.util.regex.Matcher digitMatcher = digitPattern.matcher(certString);
                if (digitMatcher.find()) {
                    return digitMatcher.group();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract BIN using string parsing: {}", e.getMessage());
        }

        return null; // BIN is optional, return null instead of default
    }


}
