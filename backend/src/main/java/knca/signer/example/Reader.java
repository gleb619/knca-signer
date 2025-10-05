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

            // Display header
            log.debug("============================================");
            log.debug("          CERTIFICATE READER");
            log.debug("============================================");
            log.debug("Found {} certificate(s) in directory: {}", certificates.size(), config.getCertsPath());

            // Print information for each certificate
            if (certificates.isEmpty()) {
                log.debug("No certificates found in the specified directory.");
                log.debug("Make sure certificates are generated first using the Generator class.");
            } else {
                for (CertificateInfo certInfo : certificates) {
                    log.debug("=== Certificate: {} ===", certInfo.getFilename());
                    log.debug("Type: {}", certInfo.getType());
                    log.debug("Serial Number: {}", certInfo.getSerialNumber());
                    log.debug("Issuer: {}", reader.formatDN(certInfo.getIssuer()));
                    log.debug("Subject: {}", reader.formatDN(certInfo.getSubject()));
                    log.debug("Valid From: {}", certInfo.getNotBefore());
                    log.debug("Valid Until: {}", certInfo.getNotAfter());
                    log.debug("Public Key: {} ({} bits)", certInfo.getPublicKeyAlgorithm(), certInfo.getKeySize());

                    if (!"N/A".equals(certInfo.getEmail()) && certInfo.getEmail() != null) {
                        log.debug("Email: {}", certInfo.getEmail());
                    }
                    if (!"N/A".equals(certInfo.getIin()) && certInfo.getIin() != null) {
                        log.debug("IIN: {}", certInfo.getIin());
                    }
                    if (certInfo.getBin() != null) {
                        log.debug("BIN: {}", certInfo.getBin());
                    }
                    log.debug("============================================");
                }

                // Summary
                long caCount = certificates.stream().filter(c -> "CA".equals(c.getType())).count();
                long userCount = certificates.stream().filter(c -> "USER".equals(c.getType())).count();
                long legalCount = certificates.stream().filter(c -> "LEGAL".equals(c.getType())).count();

                log.debug("SUMMARY:");
                log.debug("========");
                log.debug("CA Certificates: {}", caCount);
                log.debug("User Certificates: {}", userCount);
                log.debug("Legal Entity Certificates: {}", legalCount);
                log.debug("Total: {}", certificates.size());
            }

        } catch (Exception e) {
            log.error("Certificate reading failed: {}", e.getMessage(), e);
            log.error("Make sure you have certificates in the certs/ directory and the KalkanProvider is properly configured.");
        }
    }

}