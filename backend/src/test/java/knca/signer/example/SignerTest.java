package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
class SignerTest {

    private java.security.Provider provider;
    private java.security.Provider realProvider;
    private ApplicationConfig.CertificateConfig config;

    @BeforeEach
    void setUp() throws Exception {
        // Load the real KalkanProvider using registry (same as Generator.main does)
        realProvider = KalkanRegistry.loadRealKalkanProvider();

        provider = (java.security.Provider) KalkanRegistry.createKalkanProvider().getRealObject();
        config = new ApplicationConfig.CertificateConfig(
                "certs/",
                "certs/ca.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );
    }

}
