package knca.signer.example;

import io.vertx.core.Vertx;
import knca.signer.config.ApplicationConfig;
import knca.signer.config.BeanFactory;
import knca.signer.service.CertificateService;
import lombok.extern.slf4j.Slf4j;

/**
 * Main entry point for Xml signing.
 * Demonstrates signing with bean factory dependency injection.
 */
@Slf4j
public class Signer {

    public static void main(String[] args) {
        try {
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

            // Create Vertx instance for BeanFactory
            Vertx vertx = Vertx.vertx();

            // Create bean factory and initialize services
            BeanFactory beanFactory = new BeanFactory(vertx, ApplicationConfig.builder()
                    .certificate(config)
                    .build());
            beanFactory.init();

            // Get CertificateService from bean factory
            CertificateService certificateService = beanFactory.getCertificateService();

            log.info("Initialized CertificateService via BeanFactory");

            // Example 1: Sign using current storage mode
            signXmlWithCurrentMode(certificateService);

        } catch (Exception e) {
            log.error("Xml sign creation failed: %s".formatted(e.getMessage()), e);
        }
    }

    /**
     * Demonstrate XML signing using CertificateService from bean factory.
     * Automatically uses the configured storage mode (file or in-memory).
     */
    private static void signXmlWithCurrentMode(CertificateService certificateService) throws Exception {
        log.info("=== Demonstrating XML Signing with Current Storage Mode ===");

        // Create sample XML to sign
        String xmlData = """
                <?xml version="1.0" encoding="UTF-8"?>
                <Document>
                    <Header>
                        <Title>Test XML Document</Title>
                        <Version>1.0</Version>
                    </Header>
                    <Body>
                        <Content>This is test XML content to be digitally signed.</Content>
                        <Timestamp>2025-01-24T12:00:00Z</Timestamp>
                    </Body>
                </Document>
                """.trim();

        log.info("Original XML to sign:");
        log.info(xmlData);
        log.info("");

        // Sign using CertificateService (will respect storageMode from app.yaml)
        String signedXml = certificateService.signXml(xmlData, "user");

        log.info("✅ XML signing completed successfully!");
        log.info("Signed XML:");
        log.info(signedXml);
        log.info("");

        // Note: XML signature verification could be performed here if needed
        log.info("Note: XML signature verification can be performed using CertificateService.validateXmlSignature()");

    }
}
