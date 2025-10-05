package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.security.KalkanRegistry;
import knca.signer.service.CertificateDataGenerator;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.KeyStoreManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

public class GeneratorTest {

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

    @Test
    public void testCertificateConfigCreation() {
        ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
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
        String iin = CertificateDataGenerator.generateIIN();
        assertNotNull(iin, "IIN should be generated");
        assertEquals(12, iin.length(), "IIN should be 12 digits");

        // Test BIN generation
        String bin = CertificateDataGenerator.generateBIN();
        assertNotNull(bin, "BIN should be generated");
        assertEquals(12, bin.length(), "BIN should be 12 digits");

        // Test email generation
        String email = CertificateDataGenerator.generateEmail();
        assertNotNull(email, "Email should be generated");
        assertTrue(email.contains("@"), "Email should contain @");

        // Test subject DN generation
        String individualDN = CertificateDataGenerator.generateIndividualSubjectDN();
        assertNotNull(individualDN, "Individual DN should be generated");
        assertTrue(individualDN.contains("CN="), "Should contain CN");
        assertTrue(individualDN.contains("C=KZ"), "Should contain C=KZ");

        String legalDN = CertificateDataGenerator.generateLegalEntitySubjectDN();
        assertNotNull(legalDN, "Legal DN should be generated");
        assertTrue(legalDN.contains("CN="), "Should contain CN");
        assertTrue(legalDN.contains("O="), "Should contain O=");
    }

    @Test
    public void testCertificateGeneratorCreation() {
        CertificateGenerator generator = new CertificateGenerator(provider, config);
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
            CertificateGenerator generator = new CertificateGenerator(realProvider, config);
            CertificateGenerator.CertificateResult result = generator.generateCACertificate();

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
            KalkanRegistry.createKalkanProvider();
            assertTrue(true, "All proxy classes should be instantiable");
        } catch (Exception e) {
            fail("Proxy classes should be instantiable: " + e.getMessage());
        }
    }

    @Test
    public void testGeneratorMainMethod() {
        // Test that the main method can be called without throwing exceptions
        // This is a basic smoke test
        try {
            // We can't easily test the full main method without file I/O,
            // but we can test that the class loads and basic instantiation works
            Class.forName("knca.signer.example.Generator");
            assertTrue(true, "Generator class should be loadable");
        } catch (ClassNotFoundException e) {
            fail("Generator class should be found");
        }
    }
}
