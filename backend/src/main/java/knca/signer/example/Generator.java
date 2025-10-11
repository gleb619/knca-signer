package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateStorageService;
import lombok.extern.slf4j.Slf4j;

/**
 * Main entry point for certificate generation.
 * Now uses the new instance-based CertificateGenerator.
 */
@Slf4j
public class Generator {

    public static void main(String[] args) {
        try {
            // Load and register the KalkanProvider
            java.security.Provider realProvider = KalkanRegistry.loadRealKalkanProvider();
            String providerName = realProvider.getName();
            log.info("Registered provider: " + providerName);

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

            // Create registry service
            var registryService = new CertificateStorageService(new CertificateStorageService.CertificateStorage());

            // Create and run certificate generator
            CertificateGenerator generator = new CertificateGenerator(realProvider, config, registryService);
            generator.generateAllCertificates();

        } catch (Exception e) {
            log.error("Certificate generation failed: %s".formatted(e.getMessage()), e);
        }
    }
}
