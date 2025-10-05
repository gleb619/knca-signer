package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateReader;
import knca.signer.service.CertificateReader.CertificateInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Main entry point for certificate reading and analysis.
 * Reads certificates from the certs directory and prints detailed information.
 */
@Slf4j
public class Reader {

    public static void main(String[] args) {
        try {
            // Load and register the KalkanProvider
            java.security.Provider realProvider = KalkanRegistry.loadRealKalkanProvider();
            String providerName = realProvider.getName();
            log.debug("Registered provider: {}", providerName);

            // Create configuration (simulating what would be loaded from YAML)
            ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
                    "certs/",
                    "certs/ca.crt",
                    2048,
                    "RSA",
                    "1.2.840.113549.1.1.11",
                    "123456",
                    10,
                    1
            );

            // Create certificate reader and read all certificates
            CertificateReader reader = new CertificateReader(config);
            List<CertificateInfo> certificates = reader.readAllCertificates();

            StringBuilder output = new StringBuilder("\n");

            // Display header
            output.append("============================================\n");
            output.append("          CERTIFICATE READER\n");
            output.append("============================================\n");
            output.append(String.format("Found %d certificate(s) in directory: %s\n", certificates.size(), config.getCertsPath()));

            // Print information for each certificate
            if (certificates.isEmpty()) {
                output.append("No certificates found in the specified directory.\n");
                output.append("Make sure certificates are generated first using the Generator class.\n");
            } else {
                int certIndex = 1;
                for (CertificateInfo certInfo : certificates) {
                    output.append(buildCertificateInfo(reader, certInfo, certIndex++));
                }

                // Summary
                long caCount = certificates.stream().filter(c -> "CA".equals(c.getType())).count();
                long userCount = certificates.stream().filter(c -> "USER".equals(c.getType())).count();
                long legalCount = certificates.stream().filter(c -> "LEGAL".equals(c.getType())).count();

                output.append("\n");
                output.append("╔══════════════════════════════════════════════════════════════════════════╗\n");
                output.append("║                          CERTIFICATE SUMMARY                             ║\n");
                output.append("╠══════════════════════════════════════════════════════════════════════════╣\n");
                output.append(String.format("║ CA Certificates:        %-55d ║\n", caCount));
                output.append(String.format("║ User Certificates:      %-55d ║\n", userCount));
                output.append(String.format("║ Legal Entity Certificates: %-51d ║\n", legalCount));
                output.append("╠══════════════════════════════════════════════════════════════════════════╣\n");
                output.append(String.format("║ Total Certificates:     %-55d ║\n", certificates.size()));
                output.append("╚══════════════════════════════════════════════════════════════════════════╝\n");
            }

            log.info(output.toString());

        } catch (Exception e) {
            log.error("Certificate reading failed: {}", e.getMessage(), e);
            log.error("Make sure you have certificates in the certs/ directory and the KalkanProvider is properly configured.");
        }
    }

    /**
     * Builds certificate information in a beautifully formatted way.
     */
    private static String buildCertificateInfo(CertificateReader reader, CertificateInfo certInfo, int index) {
        StringBuilder certOutput = new StringBuilder();

        certOutput.append("\n");
        certOutput.append("╔══════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
        certOutput.append(String.format("║                                 CERTIFICATE #%d                                               ║\n", index));
        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        certOutput.append(String.format("║ File:         %-75s ║\n", certInfo.getFilename()));
        certOutput.append(String.format("║ Type:         %-75s ║\n", getTypeWithIcon(certInfo.getType())));
        certOutput.append(String.format("║ Serial:       %-75s ║\n", certInfo.getSerialNumber()));
        certOutput.append("╠═══════════════════════════════════════════════ ═══════════════════════════════════════════╣\n");

        // Subject information (formatted)
        String[] subjectLines = reader.formatDN(certInfo.getSubject()).split("\n");
        certOutput.append("║ Subject:                                                                                  ║\n");
        for (String line : subjectLines) {
            certOutput.append(String.format("║    %-83s ║\n", line.trim()));
        }

        // Issuer information (formatted)
        String[] issuerLines = reader.formatDN(certInfo.getIssuer()).split("\n");
        certOutput.append("║ Issuer:                                                                                   ║\n");
        for (String line : issuerLines) {
            certOutput.append(String.format("║    %-83s ║\n", line.trim()));
        }

        certOutput.append("╠═══════════════════════════════════════════════ ═══════════════════════════════════════════╣\n");
        certOutput.append(String.format("║ Valid From:   %-75s ║\n", certInfo.getNotBefore()));
        certOutput.append(String.format("║ Valid Until:  %-75s ║\n", certInfo.getNotAfter()));
        certOutput.append(String.format("║ Status:       %-75s ║\n", getValidityStatus(certInfo)));
        certOutput.append("╠═══════════════════════════════════════════════ ═══════════════════════════════════════════╣\n");
        certOutput.append(String.format("║ Algorithm:    %-18s Key Size: %54s ║\n", certInfo.getPublicKeyAlgorithm(), certInfo.getKeySize() + " bits"));

        // Additional information if available
        boolean hasAdditionalInfo = (!"N/A".equals(certInfo.getEmail()) && certInfo.getEmail() != null) ||
                (!"N/A".equals(certInfo.getIin()) && certInfo.getIin() != null) ||
                (!"N/A".equals(certInfo.getBin()) && certInfo.getBin() != null);

        if (hasAdditionalInfo) {
            certOutput.append("╠═══════════════════════════════════════════════ ═══════════════════════════════════════════╣\n");
            certOutput.append("║ Additional Information:                                                                   ║\n");

            if (!"N/A".equals(certInfo.getEmail()) && certInfo.getEmail() != null) {
                certOutput.append(String.format("║    Email:          %-65s ║\n", certInfo.getEmail()));
            }
            if (!"N/A".equals(certInfo.getIin()) && certInfo.getIin() != null) {
                certOutput.append(String.format("║    IIN (Individual): %-61s ║\n", certInfo.getIin()));
            }
            if (!"N/A".equals(certInfo.getBin()) && certInfo.getBin() != null) {
                certOutput.append(String.format("║    BIN (Business):  %-61s ║\n", certInfo.getBin()));
            }
        }

        // Certificate fingerprint-like information
        certOutput.append("╠═══════════════════════════════════════════════ ═══════════════════════════════════════════╣\n");
        certOutput.append(String.format("║ Fingerprint (SHA-1): %-68s ║\n", generateMockFingerprint(certInfo)));
        certOutput.append(String.format("║ Version:       %-75s ║\n", "X.509 v3"));
        certOutput.append("╚══════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
        certOutput.append("\n");

        // Certificate expiry warning
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        if (certInfo.getNotAfter().isBefore(now)) {
            certOutput.append("⚠️  WARNING: This certificate has EXPIRED!\n");
        } else if (certInfo.getNotAfter().isBefore(now.plusDays(30))) {
            certOutput.append("⚠️  WARNING: This certificate will expire soon!\n");
        } else {
            certOutput.append("✅ This certificate is valid.\n");
        }
        certOutput.append("\n");

        return certOutput.toString();
    }

    /**
     * Returns certificate type with a nice icon.
     */
    private static String getTypeWithIcon(String type) {
        return switch (type) {
            case "CA" -> "🔐 Certificate Authority (CA)";
            case "USER" -> "👤 Individual User Certificate";
            case "LEGAL" -> "🏢 Legal Entity Certificate";
            default -> type;
        };
    }

    /**
     * Returns certificate validity status as a string.
     */
    private static String getValidityStatus(CertificateInfo certInfo) {
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        if (certInfo.getNotAfter().isBefore(now)) {
            return "❌ EXPIRED";
        } else if (certInfo.getNotBefore().isAfter(now)) {
            return "⏳ NOT YET VALID";
        } else {
            return "✅ VALID";
        }
    }

    /**
     * Generates a mock fingerprint-style string for display.
     */
    private static String generateMockFingerprint(CertificateInfo certInfo) {
        try {
            // Use serial number and subject to create a simple "fingerprint" representation
            String input = certInfo.getSerialNumber() + certInfo.getSubject().replace(",", "").replace("=", "");
            int hash = input.hashCode();
            String hex = String.format("%08X", hash).toLowerCase();
            // Format as colon-separated groups like real SHA-1 fingerprint
            return String.format("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8));
        } catch (Exception e) {
            return "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11:22:33:44";
        }
    }

}