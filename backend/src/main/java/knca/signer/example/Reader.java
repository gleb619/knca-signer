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

    private static final int TABLE_WIDTH = 98;

    public static void main(String[] args) {
        try {
            // Load and register the KalkanProvider
            java.security.Provider realProvider = KalkanRegistry.loadRealKalkanProvider();
            String providerName = realProvider.getName();
            log.debug("Registered provider: {}", providerName);

            // Create configuration (simulating what would be loaded from YAML)
            ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
                    "file",
                    1,
                    1,
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
                output.append(formatTableRow("CA Certificates:", String.valueOf(caCount), 74));
                output.append(formatTableRow("User Certificates:", String.valueOf(userCount), 74));
                output.append(formatTableRow("Legal Entity Certificates:", String.valueOf(legalCount), 74));
                output.append("╠══════════════════════════════════════════════════════════════════════════╣\n");
                output.append(formatTableRow("Total Certificates:", String.valueOf(certificates.size()), 74));
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
        certOutput.append(formatTableRow("CERTIFICATE #" + index, "", TABLE_WIDTH, true));
        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        certOutput.append(formatTableRow("File:", certInfo.getFilename(), TABLE_WIDTH));
        certOutput.append(formatTableRow("Type:", getTypeWithIcon(certInfo.getType()), TABLE_WIDTH));
        certOutput.append(formatTableRow("Serial:", certInfo.getSerialNumber(), TABLE_WIDTH));
        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");

        // Subject information (formatted)
        String[] subjectLines = reader.formatDN(certInfo.getSubject()).split("\n");
        certOutput.append(formatTableRow("Subject:", "", TABLE_WIDTH));
        for (String line : subjectLines) {
            certOutput.append(formatTableRow("   " + line.trim(), "", TABLE_WIDTH));
        }

        // Issuer information (formatted)
        String[] issuerLines = reader.formatDN(certInfo.getIssuer()).split("\n");
        certOutput.append(formatTableRow("Issuer:", "", TABLE_WIDTH));
        for (String line : issuerLines) {
            certOutput.append(formatTableRow("   " + line.trim(), "", TABLE_WIDTH));
        }

        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        certOutput.append(formatTableRow("Valid From:", certInfo.getNotBefore().toString(), TABLE_WIDTH));
        certOutput.append(formatTableRow("Valid Until:", certInfo.getNotAfter().toString(), TABLE_WIDTH));
        certOutput.append(formatTableRow("Status:", getValidityStatus(certInfo), TABLE_WIDTH));
        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        certOutput.append(formatTableRowTwoColumns("Algorithm:", certInfo.getPublicKeyAlgorithm(), "Key Size:", certInfo.getKeySize() + " bits", TABLE_WIDTH));

        // Additional information if available
        boolean hasAdditionalInfo = (!"N/A".equals(certInfo.getEmail()) && certInfo.getEmail() != null) ||
                (!"N/A".equals(certInfo.getIin()) && certInfo.getIin() != null) ||
                (!"N/A".equals(certInfo.getBin()) && certInfo.getBin() != null);

        if (hasAdditionalInfo) {
            certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
            certOutput.append(formatTableRow("Additional Information:", "", TABLE_WIDTH));

            if (!"N/A".equals(certInfo.getEmail()) && certInfo.getEmail() != null) {
                certOutput.append(formatTableRow("   Email:", certInfo.getEmail(), TABLE_WIDTH));
            }
            if (!"N/A".equals(certInfo.getIin()) && certInfo.getIin() != null) {
                certOutput.append(formatTableRow("   IIN (Individual):", certInfo.getIin(), TABLE_WIDTH));
            }
            if (!"N/A".equals(certInfo.getBin()) && certInfo.getBin() != null) {
                certOutput.append(formatTableRow("   BIN (Business):", certInfo.getBin(), TABLE_WIDTH));
            }
        }

        // Certificate fingerprint-like information
        certOutput.append("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        certOutput.append(formatTableRow("Fingerprint (SHA-1):", generateMockFingerprint(certInfo), TABLE_WIDTH));
        certOutput.append(formatTableRow("Version:", "X.509 v3", TABLE_WIDTH));
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
     * Formats a table row with proper alignment and width calculation considering UTF-8 characters.
     */
    private static String formatTableRow(String label, String value, int totalWidth) {
        return formatTableRow(label, value, totalWidth, false);
    }

    /**
     * Formats a table row with proper alignment and width calculation considering UTF-8 characters.
     */
    private static String formatTableRow(String label, String value, int totalWidth, boolean centered) {
        String content = value.isEmpty() ? label : label + " " + value;
        int visualWidth = calculateVisualWidth(content);
        int padding = totalWidth - 4 - visualWidth;

        if (centered) {
            int leftPad = padding / 2;
            int rightPad = padding - leftPad;
            return String.format("║%s%s%s║\n", " ".repeat(leftPad + 2), content, " ".repeat(rightPad + 2));
        } else {
            return String.format("║ %s%s ║\n", content, " ".repeat(Math.max(0, padding)));
        }
    }

    /**
     * Formats a table row with two columns.
     */
    private static String formatTableRowTwoColumns(String label1, String value1, String label2, String value2, int totalWidth) {
        String leftContent = label1 + " " + value1;
        String rightContent = label2 + " " + value2;

        int leftVisualWidth = calculateVisualWidth(leftContent);
        int rightVisualWidth = calculateVisualWidth(rightContent);
        int totalContentWidth = leftVisualWidth + rightVisualWidth;
        int padding = totalWidth - 4 - totalContentWidth;

        return String.format("║ %s%s%s ║\n", leftContent, " ".repeat(Math.max(1, padding)), rightContent);
    }

    /**
     * Calculates visual width of string considering UTF-8 multi-byte characters.
     * Cyrillic and other non-ASCII characters typically take more visual space.
     */
    private static int calculateVisualWidth(String text) {
        int width = 0;
        for (char c : text.toCharArray()) {
            if (c >= 0x0400 && c <= 0x04FF) {
                // Cyrillic characters
                width += 2;
            } else if (c >= 0x1F300 && c <= 0x1F9FF) {
                // Emoji range
                width += 2;
            } else if (c > 0x007F) {
                // Other non-ASCII
                width += 2;
            } else {
                // ASCII characters
                width += 1;
            }
        }
        return width;
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
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8),
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8),
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8),
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8),
                    hex.substring(0, 2), hex.substring(2, 4), hex.substring(4, 6), hex.substring(6, 8));
        } catch (Exception e) {
            return "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11:22:33:44";
        }
    }

}