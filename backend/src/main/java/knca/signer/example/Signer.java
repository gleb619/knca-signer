package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import lombok.extern.slf4j.Slf4j;

/**
 * Main entry point for Xml signing.
 */
@Slf4j
public class Signer {

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

        } catch (Exception e) {
            log.error("Xml sign creation failed: %s".formatted(e.getMessage()), e);
        }
    }
}
