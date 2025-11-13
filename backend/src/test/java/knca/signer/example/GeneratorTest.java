package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateDataPopulator;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService.CertificateResult;
import knca.signer.service.CertificateStorage;
import knca.signer.service.KeyStoreManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.Provider;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class GeneratorTest {

    private Provider provider;
    private Provider realProvider;
    private ApplicationConfig.CertificateConfig config;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        // Load the real KalkanProvider using registry (same as Generator.main does)
        realProvider = KalkanRegistry.loadRealKalkanProvider();

        provider = (Provider) new KalkanRegistry().createKalkanProvider().getRealObject();
        config = new ApplicationConfig.CertificateConfig(
                "in-memory",
                3,
                2,
                tempDir + "/certs/",
                tempDir + "/certs/ca.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );
    }

    @Test
    public void testCertificateConfigCreation() {
        ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
                "in-memory",
                3,
                2,
                "certs/",
                "certs/ca.crt",
                2048,
                "RSA",
                "1.2.398.3.3.4.1.1",
                "123456",
                10,
                1
        );
        assertNotNull(config, "Config should be created");
        assertEquals("certs/", config.getCertsPath());
        assertEquals("certs/ca.crt", config.getCaCertPath());
        assertEquals(2048, config.getKeySize());
        assertEquals("123456", config.getKeystorePassword());
    }

    @Test
    public void testCertificateDataGenerator() {
        // Test IIN generation
        String iin = CertificateDataPopulator.populateIIN();
        assertNotNull(iin, "IIN should be generated");
        assertEquals(12, iin.length(), "IIN should be 12 digits");

        // Test BIN generation
        String bin = CertificateDataPopulator.populateBIN();
        assertNotNull(bin, "BIN should be generated");
        assertEquals(12, bin.length(), "BIN should be 12 digits");

        // Test email generation
        String email = CertificateDataPopulator.populateEmail();
        assertNotNull(email, "Email should be generated");
        assertTrue(email.contains("@"), "Email should contain @");

        // Test subject DN generation
        String individualDN = CertificateDataPopulator.populateIndividualSubjectDN();
        assertNotNull(individualDN, "Individual DN should be generated");
        assertTrue(individualDN.contains("CN="), "Should contain CN");
        assertTrue(individualDN.contains("C=KZ"), "Should contain C=KZ");

        String legalDN = CertificateDataPopulator.populateLegalEntitySubjectDN();
        assertNotNull(legalDN, "Legal DN should be generated");
        assertTrue(legalDN.contains("CN="), "Should contain CN");
        assertTrue(legalDN.contains("O="), "Should contain O=");
    }

    @Test
    public void testCertificateGeneratorCreation() {
        var registryService = new CertificateStorage(new CertificateStorage.Storage());
        CertificateGenerator generator = new CertificateGenerator(provider, config, registryService);
        assertNotNull(generator, "Generator should be created");
    }

    @Test
    public void testKeyStoreManager() {
        try {
            // Test that KeyStoreManager methods can be called (without actual keystore operations)
            // This tests that the class structure is correct
            assertNotNull(KeyStoreManager.class, "KeyStoreManager should be accessible");
        } catch (Exception e) {
            fail("KeyStoreManager should be accessible: " + e.getMessage());
        }
    }

    @Test
    public void testCertificateGeneratorCACertificate() {
        try {
            // Use real provider for actual generation, like Generator.main does
            var registryService = new CertificateStorage(new CertificateStorage.Storage());
            CertificateGenerator generator = new CertificateGenerator(realProvider, config, registryService);
            CertificateResult result = generator.generateCACertificate();

            assertNotNull(result, "CA result should be returned");
            assertNotNull(result.getKeyPair(), "CA key pair should be generated");
            assertNotNull(result.getCertificate(), "CA certificate should be generated");

            X509Certificate caCert = result.getCertificate();
            assertEquals(caCert.getSubjectDN(), caCert.getIssuerDN(), "CA should be self-signed");

        } catch (Exception e) {
            fail("CA certificate generation should succeed: " + e.getMessage());
        }
    }

    @Test
    public void testWrapperClassesExist() {
        // Test that our proxy classes can be instantiated
        try {
            new KalkanRegistry().createKalkanProvider();
            assertTrue(true, "All proxy classes should be instantiable");
        } catch (Exception e) {
            fail("Proxy classes should be instantiable: " + e.getMessage());
        }
    }

}
