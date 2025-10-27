package knca.signer.kalkan;

import knca.signer.kalkan.api.*;
import knca.signer.service.CertificateDataPopulator;
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

    private static final KalkanRegistry REGISTRY = new KalkanRegistry();
    
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
        return REGISTRY.createAlgorithmIdentifier(objectId, parameters);
    }

    public static KalkanProxy createASN1EncodableVector() {
        return REGISTRY.createASN1EncodableVector();
    }

    public static KalkanProxy createDERObjectIdentifier(String oid) {
        return REGISTRY.createDERObjectIdentifier(oid);
    }

    public static KalkanProxy createDERSequence(Object vector) {
        return REGISTRY.createDERSequence(vector);
    }

    public static KalkanProxy createDERInteger(byte[] serNum) {
        return REGISTRY.createDERInteger(serNum);
    }

    public static KalkanProxy createDERNull() {
        return REGISTRY.createDERNull();
    }

    public static KalkanProxy createDERUTF8String(String value) {
        return REGISTRY.createDERUTF8String(value);
    }

    public static KalkanProxy createDERTaggedObject(boolean explicit, int tagNo, Object obj) {
        return REGISTRY.createDERTaggedObject(explicit, tagNo, obj);
    }

    public static KalkanProxy createGeneralName(int tag, Object name) {
        return REGISTRY.createGeneralName(tag, name);
    }

    public static KalkanProxy createGeneralNames(Object sequence) {
        return REGISTRY.createGeneralNames(sequence);
    }

    public static KalkanProxy createX509Name(String name) {
        return REGISTRY.createX509Name(name);
    }

    public static KalkanProxy createTime(java.util.Date time) {
        return REGISTRY.createTime(time);
    }

    public static KalkanProxy createBasicConstraints(boolean ca) {
        return REGISTRY.createBasicConstraints(ca);
    }

    public static KalkanProxy createKeyUsage(int keyUsage) {
        return REGISTRY.createKeyUsage(keyUsage);
    }

    public static KalkanProxy createSubjectPublicKeyInfo(Object seq) {
        return REGISTRY.createSubjectPublicKeyInfo(seq);
    }

    @Deprecated(forRemoval = true)
    public static V3TBSCertificateGenerator createV3TBSCertificateGenerator() {
        return REGISTRY.createV3TBSCertificateGenerator();
    }

    public static X509ExtensionsGenerator createX509ExtensionsGenerator() {
        return REGISTRY.createX509ExtensionsGenerator();
    }

    public static X509V3CertificateGenerator createX509V3CertificateGenerator() {
        return REGISTRY.createX509V3CertificateGenerator();
    }

    public static ASN1EncodableVector createASN1EncodableVectorWrapper() {
        return REGISTRY.createASN1EncodableVectorWrapper();
    }

    public static PEMWriter createPEMWriter(java.io.Writer writer) {
        return REGISTRY.createPEMWriter(writer);
    }

    public static TBSCertificateManager createTBSCertificateManager() {
        return REGISTRY.createTBSCertificateManager();
    }

    public static KalkanProxy createKalkanPKCS12Keystore() {
        return REGISTRY.createKalkanPKCS12Keystore();
    }

    public static KalkanProxy createKalkanJKSKeystore() {
        return REGISTRY.createKalkanJKSKeystore();
    }

    // ========== TBS Certificate Utility Methods ==========

    public static KalkanProxy createSubjectPublicKeyInfo(PublicKey publicKey) {
        Object seq = REGISTRY.createASN1SequenceFromPublicKey(publicKey);
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
            if (certString.contains(CertificateDataPopulator.IIN_OID)) {
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
            if (certString.contains(CertificateDataPopulator.BIN_OID)) {
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
