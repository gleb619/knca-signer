package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.security.Provider;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
class SignerTest {

    private Provider provider;
    private Provider realProvider;
    private ApplicationConfig.CertificateConfig config;

    @BeforeEach
    void setUp() throws Exception {
        // Load the real KalkanProvider using registry (same as Generator.main does)
        realProvider = KalkanRegistry.loadRealKalkanProvider();

        provider = (Provider) new KalkanRegistry().createKalkanProvider().getRealObject();
        config = new ApplicationConfig.CertificateConfig(
                "in-memory",
                3,
                2,
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
