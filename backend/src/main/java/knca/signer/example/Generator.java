package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import knca.signer.service.CertificateValidator;
import lombok.extern.slf4j.Slf4j;

import java.security.Provider;

/**
 * Main entry point for certificate generation.
 * Now uses the new instance-based CertificateGenerator.
 */
@Slf4j
public class Generator {

    public static void main(String[] args) {
        try {
            // Load and register the KalkanProvider
            Provider realProvider = KalkanRegistry.loadRealKalkanProvider();
            String providerName = realProvider.getName();
            log.info("Registered provider: {}", providerName);

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

            // Create registry service
            var registryService = new CertificateStorage(new CertificateStorage.Storage());

            // Create services like in BeanFactory
            var generationService = new CertificateGenerator(realProvider, config, registryService);
            var validationService = new CertificateValidator(realProvider, registryService);
            var certificateService = new CertificateService(realProvider, config, registryService, generationService, validationService);

            // Initialize to generate/load certificates based on mode
            certificateService.init();
            log.info("CertificateService.init() completed, checking storage...");

            // Generate demonstration certificates for fixed names (for examples)
            generationService.generateAllCertificates();
            log.info("Generated demonstration certificates (user.crt, user.key, etc.)");

        } catch (Exception e) {
            log.error("Certificate generation failed: %s".formatted(e.getMessage()), e);
        }
    }
}
