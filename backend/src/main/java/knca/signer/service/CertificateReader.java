package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.security.KalkanAdapter;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

/**
 * Service for reading and analyzing certificates from the filesystem.
 * Supports reading CA, user, and legal entity certificates.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateReader {

    private final ApplicationConfig.CertificateConfig config;

    /**
     * Read and analyze all certificates in the certs directory.
     */
    public List<CertificateInfo> readAllCertificates() throws Exception {
        List<CertificateInfo> certificates = new ArrayList<>();
        Path certsDir = Paths.get(config.getCertsPath());

        if (!Files.exists(certsDir)) {
            log.warn("Certificates directory does not exist: {}", config.getCertsPath());
            return certificates;
        }

        log.info("Reading certificates from directory: {}", config.getCertsPath());

        // Read CA certificates
        certificates.addAll(readCACertificates(certsDir));

        // Read user certificates
        certificates.addAll(readUserCertificates(certsDir));

        // Read legal certificates
        certificates.addAll(readLegalCertificates(certsDir));

        return certificates;
    }

    /**
     * Read CA certificates from .crt and .pem files.
     */
    private List<CertificateInfo> readCACertificates(Path certsDir) throws Exception {
        List<CertificateInfo> caCerts = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(certsDir, 1)) {
            paths.filter(path -> {
                String filename = path.getFileName().toString();
                return Files.isRegularFile(path) &&
                        (filename.startsWith("ca") || filename.contains("ca")) &&
                        (filename.endsWith(".crt") || filename.endsWith(".pem"));
            }).forEach(caCertPath -> {
                try {
                    X509Certificate cert = loadCertificateFromFile(caCertPath);
                    CertificateInfo info = extractCertificateInfo(cert, "CA", caCertPath.getFileName().toString());
                    caCerts.add(info);
                    log.info("Read CA certificate: {}", caCertPath.getFileName());
                } catch (Exception e) {
                    log.warn("Failed to read CA certificate {}: {}", caCertPath.getFileName(), e.getMessage());
                }
            });
        }

        return caCerts;
    }

    /**
     * Read user certificates from .crt/.pem files and .p12 keystores.
     */
    private List<CertificateInfo> readUserCertificates(Path certsDir) throws Exception {
        List<CertificateInfo> userCerts = new ArrayList<>();

        // First try to read from keystore
        Path p12Path = certsDir.resolve("user.p12");
        if (Files.exists(p12Path)) {
            try {
                X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                        p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
                CertificateInfo info = extractCertificateInfo(cert, "USER", "user.p12");
                userCerts.add(info);
                log.info("Read user certificate from keystore: user.p12");
                return userCerts; // Return early if keystore read successful
            } catch (Exception e) {
                log.warn("Failed to read user certificate from keystore, trying individual files: {}", e.getMessage());
            }
        }

        // Fallback to individual certificate files
        try (Stream<Path> paths = Files.walk(certsDir, 1)) {
            paths.filter(path -> {
                String filename = path.getFileName().toString();
                return Files.isRegularFile(path) &&
                        (filename.startsWith("user") || filename.contains("user")) &&
                        (filename.endsWith(".crt") || filename.endsWith(".pem"));
            }).forEach(userCertPath -> {
                try {
                    X509Certificate cert = loadCertificateFromFile(userCertPath);
                    CertificateInfo info = extractCertificateInfo(cert, "USER", userCertPath.getFileName().toString());
                    userCerts.add(info);
                    log.info("Read user certificate: {}", userCertPath.getFileName());
                } catch (Exception e) {
                    log.warn("Failed to read user certificate {}: {}", userCertPath.getFileName(), e.getMessage());
                }
            });
        }

        return userCerts;
    }

    /**
     * Read legal entity certificates from .crt/.pem files and .p12 keystores.
     */
    private List<CertificateInfo> readLegalCertificates(Path certsDir) throws Exception {
        List<CertificateInfo> legalCerts = new ArrayList<>();

        // First try to read from keystore
        Path p12Path = certsDir.resolve("legal.p12");
        if (Files.exists(p12Path)) {
            try {
                X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                        p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
                CertificateInfo info = extractCertificateInfo(cert, "LEGAL", "legal.p12");
                legalCerts.add(info);
                log.info("Read legal certificate from keystore: legal.p12");
                return legalCerts; // Return early if keystore read successful
            } catch (Exception e) {
                log.warn("Failed to read legal certificate from keystore, trying individual files: {}", e.getMessage());
            }
        }

        // Fallback to individual certificate files
        try (Stream<Path> paths = Files.walk(certsDir, 1)) {
            paths.filter(path -> {
                String filename = path.getFileName().toString();
                return Files.isRegularFile(path) &&
                        (filename.startsWith("legal") || filename.contains("legal")) &&
                        (filename.endsWith(".crt") || filename.endsWith(".pem"));
            }).forEach(legalCertPath -> {
                try {
                    X509Certificate cert = loadCertificateFromFile(legalCertPath);
                    CertificateInfo info = extractCertificateInfo(cert, "LEGAL", legalCertPath.getFileName().toString());
                    legalCerts.add(info);
                    log.info("Read legal certificate: {}", legalCertPath.getFileName());
                } catch (Exception e) {
                    log.warn("Failed to read legal certificate {}: {}", legalCertPath.getFileName(), e.getMessage());
                }
            });
        }

        return legalCerts;
    }

    /**
     * Load certificate from PEM/DER file.
     */
    private X509Certificate loadCertificateFromFile(Path certPath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certPath.toFile())) {
            return (X509Certificate) certFactory.generateCertificate(fis);
        }
    }

    /**
     * Extract comprehensive information from a certificate.
     */
    public CertificateInfo extractCertificateInfo(X509Certificate cert, String type, String filename) {
        String serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
        String issuer = cert.getIssuerDN().getName();
        String subject = cert.getSubjectDN().getName();

        LocalDateTime notBefore = LocalDateTime.ofInstant(cert.getNotBefore().toInstant(), ZoneId.systemDefault());
        LocalDateTime notAfter = LocalDateTime.ofInstant(cert.getNotAfter().toInstant(), ZoneId.systemDefault());

        // Extract additional metadata using KalkanAdapter
        String email = extractEmail(cert);
        String iin = extractIIN(cert);
        String bin = extractBIN(cert);

        // Extract key information
        String publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
        int keySize = extractKeySize(cert.getPublicKey());

        return CertificateInfo.builder()
                .type(type)
                .filename(filename)
                .serialNumber(serialNumber)
                .issuer(issuer)
                .subject(subject)
                .notBefore(notBefore)
                .notAfter(notAfter)
                .email(email)
                .iin(iin)
                .bin(bin)
                .publicKeyAlgorithm(publicKeyAlgorithm)
                .keySize(keySize)
                .build();
    }

    /**
     * Extract email from certificate.
     */
    public String extractEmail(X509Certificate cert) {
        try {
            // First try KalkanAdapter method
            return KalkanAdapter.extractEmailFromCertificate(cert);
        } catch (Exception e) {
            log.debug("KalkanAdapter email extraction failed, trying fallback methods: {}", e.getMessage());
            try {
                // Try standard Java API first
                Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (san.size() >= 2 && san.get(0).equals(1)) { // RFC822Name
                            return (String) san.get(1);
                        }
                    }
                }
            } catch (Exception javaException) {
                log.debug("Standard Java SAN extraction failed, trying string parsing: {}", javaException.getMessage());
            }

            // Ultimate fallback: parse from certificate string representation
            String certString = cert.toString();
            return parseEmailFromCertificateString(certString);
        }
    }

    /**
     * Extract IIN from certificate.
     */
    public String extractIIN(X509Certificate cert) {
        try {
            // First try KalkanAdapter method
            return KalkanAdapter.extractIINFromCertificate(cert);
        } catch (Exception e) {
            log.debug("KalkanAdapter IIN extraction failed, using fallback parsing: {}", e.getMessage());
            // Parse from certificate string representation
            return parseIINFromCertificateString(cert.toString());
        }
    }

    /**
     * Extract BIN from certificate.
     */
    public String extractBIN(X509Certificate cert) {
        try {
            // First try KalkanAdapter method
            return KalkanAdapter.extractBINFromCertificate(cert);
        } catch (Exception e) {
            log.debug("KalkanAdapter BIN extraction failed, using fallback parsing: {}", e.getMessage());
            // Parse from certificate string representation
            return parseBINFromCertificateString(cert.toString());
        }
    }

    /**
     * Parse email from certificate string representation (robust fallback method).
     */
    private String parseEmailFromCertificateString(String certString) {
        // Look for email in RFC822Name patterns
        if (certString.contains("RFC822Name")) {
            java.util.regex.Pattern emailPattern = java.util.regex.Pattern.compile("RFC822Name:\\s*([^,\\s]+@[\\w\\.]+)");
            java.util.regex.Matcher matcher = emailPattern.matcher(certString);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
        }

        // Look for email in subject alternative names section
        if (certString.contains("Subject Alternative Name")) {
            java.util.regex.Pattern emailPattern = java.util.regex.Pattern.compile("([^,\\s]+@[\\w\\.]+)");
            java.util.regex.Matcher matcher = emailPattern.matcher(certString.substring(certString.indexOf("Subject Alternative Name")));
            if (matcher.find()) {
                String email = matcher.group(1).trim();
                // Basic email validation
                if (email.contains("@") && !email.contains(" ")) {
                    return email;
                }
            }
        }

        // Look for emailAddress in DN
        if (certString.contains("emailAddress=")) {
            int emailStart = certString.indexOf("emailAddress=");
            int emailEnd = certString.indexOf(",", emailStart);
            if (emailEnd == -1) emailEnd = certString.length();
            String email = certString.substring(emailStart + "emailAddress=".length(), emailEnd).trim();
            if (email.contains("@") && !email.contains(" ")) {
                return email;
            }
        }

        return "N/A";
    }

    /**
     * Parse IIN from certificate string representation.
     */
    private String parseIINFromCertificateString(String certString) {
        // Look for IIN in SN field of DN
        if (certString.contains("SN=IIN") || certString.contains("SERIALNUMBER=IIN")) {
            int iinStart = certString.indexOf("SN=IIN");
            if (iinStart == -1) iinStart = certString.indexOf("SERIALNUMBER=IIN");
            if (iinStart != -1) {
                int iinEnd = certString.indexOf(",", iinStart);
                if (iinEnd == -1) iinEnd = certString.length();
                String iinPart = certString.substring(iinStart, iinEnd);
                // Extract digits after IIN prefix
                java.util.regex.Pattern iinPattern = java.util.regex.Pattern.compile("[A-Z]*IIN(\\d{12})");
                java.util.regex.Matcher matcher = iinPattern.matcher(iinPart);
                if (matcher.find()) {
                    return matcher.group(1);
                }
                // Try to find 12 consecutive digits
                java.util.regex.Pattern digitPattern = java.util.regex.Pattern.compile("\\d{12}");
                java.util.regex.Matcher digitMatcher = digitPattern.matcher(iinPart);
                if (digitMatcher.find()) {
                    return digitMatcher.group();
                }
            }
        }

        // Look for otherName IIN in extensions
        if (certString.contains(CertificateDataGenerator.IIN_OID)) {
            return extractValueFromExtensionString(certString, CertificateDataGenerator.IIN_OID);
        }

        return "N/A";
    }

    /**
     * Parse BIN from certificate string representation.
     */
    private String parseBINFromCertificateString(String certString) {
        // Look for BIN in OU field of DN
        if (certString.contains("OU=BIN") || certString.contains("ORGANIZATIONALUNITNAME=BIN")) {
            int binStart = certString.indexOf("OU=BIN");
            if (binStart == -1) binStart = certString.indexOf("ORGANIZATIONALUNITNAME=BIN");
            if (binStart != -1) {
                int binEnd = certString.indexOf(",", binStart);
                if (binEnd == -1) binEnd = certString.length();
                String binPart = certString.substring(binStart, binEnd);
                // Extract digits after BIN prefix
                java.util.regex.Pattern binPattern = java.util.regex.Pattern.compile("[A-Z]*BIN(\\d{12})");
                java.util.regex.Matcher matcher = binPattern.matcher(binPart);
                if (matcher.find()) {
                    return matcher.group(1);
                }
                // Try to find 12 consecutive digits
                java.util.regex.Pattern digitPattern = java.util.regex.Pattern.compile("\\d{12}");
                java.util.regex.Matcher digitMatcher = digitPattern.matcher(binPart);
                if (digitMatcher.find()) {
                    return digitMatcher.group();
                }
            }
        }

        // Look for otherName BIN in extensions
        if (certString.contains(CertificateDataGenerator.BIN_OID)) {
            return extractValueFromExtensionString(certString, CertificateDataGenerator.BIN_OID);
        }

        return null; // BIN is optional, return null instead of "N/A"
    }

    /**
     * Extract value from extension string representation.
     */
    private String extractValueFromExtensionString(String certString, String oid) {
        try {
            int oidIndex = certString.indexOf(oid);
            if (oidIndex >= 0) {
                String afterOid = certString.substring(oidIndex + oid.length());
                // Look for printable part or UTF8String pattern
                java.util.regex.Pattern valuePattern = java.util.regex.Pattern.compile("(UTF8String|PrintableString|IA5String)\\s*:\\s*([^\\]\\[\\n\\r\\t,]*)");
                java.util.regex.Matcher matcher = valuePattern.matcher(afterOid);
                if (matcher.find()) {
                    String value = matcher.group(2).trim();
                    if (value.length() >= 12) {
                        return value.substring(0, 12); // BIN/IIN is 12 digits
                    }
                }

                // Fallback: look for 12 consecutive digits
                java.util.regex.Pattern digitPattern = java.util.regex.Pattern.compile("\\d{12}");
                java.util.regex.Matcher digitMatcher = digitPattern.matcher(afterOid);
                if (digitMatcher.find()) {
                    return digitMatcher.group();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse extension value for OID {}: {}", oid, e.getMessage());
        }
        return null;
    }

    /**
     * Extract key size from public key.
     */
    private int extractKeySize(java.security.PublicKey publicKey) {
        try {
            if (publicKey.getAlgorithm().equals("RSA")) {
                return ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength();
            } else if (publicKey.getAlgorithm().equals("DSA")) {
                return ((java.security.interfaces.DSAPublicKey) publicKey).getParams().getP().bitLength();
            } else if (publicKey.getAlgorithm().equals("EC") || publicKey.getAlgorithm().equals("ECDSA")) {
                return ((java.security.interfaces.ECPublicKey) publicKey).getParams().getOrder().bitLength();
            }
        } catch (Exception e) {
            // Return 0 if unable to determine
        }
        return 0;
    }

    /**
     * Format DN string for better readability.
     */
    public String formatDN(String dn) {
        if (dn == null) return "N/A";
        return dn.replaceAll(",", ",\n    ");
    }

    /**
     * Data Transfer Object for certificate information.
     * Contains all metadata extracted from a certificate.
     */
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class CertificateInfo {

        private String type; // "CA" | "USER" | "LEGAL"
        private String filename;
        private String serialNumber;
        private String issuer;
        private String subject;
        private LocalDateTime notBefore;
        private LocalDateTime notAfter;
        private String email;
        private String iin;
        private String bin;
        private String publicKeyAlgorithm;
        private int keySize;
        private X509Certificate certificate;

    }

}
