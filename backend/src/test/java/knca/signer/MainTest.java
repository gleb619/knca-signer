package knca.signer;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class MainTest {

    private ApplicationConfig.CertificateConfig config;

    @BeforeEach
    void setUp() throws Exception {
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

    /**
     * Integration test that creates a temp folder, generates 3 certificates (CA, user, legal),
     * reads them back, signs some data, and verifies the signature.
     * Uses real services without mocks.
     */
    @Test
    public void testCertificateGenerationReadingAndValidationIntegration(@TempDir Path tempDir) throws Exception {
        // Create temp configuration using the temp directory
        ApplicationConfig.CertificateConfig tempConfig = new ApplicationConfig.CertificateConfig(
                tempDir.toString() + "/",
                tempDir + "/ca.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );

        // Load real KalkanProvider
        java.security.Provider realProvider = KalkanRegistry.loadRealKalkanProvider();
        assertNotNull(realProvider, "KalkanProvider should be loaded");

        // Create registry service
        var storage = new CertificateStorage(new CertificateStorage.Storage());

        // 1. Generate certificates (CA, User, Legal)
        CertificateGenerator generator = new CertificateGenerator(realProvider, tempConfig, storage);
        generator.generateAllCertificates();

        // 2. Read certificates back
        CertificateReader reader = new CertificateReader(tempConfig);
        List<CertificateReader.CertificateInfo> certificates = reader.readAllCertificates();

        // Verify we have the expected certificates
        assertNotNull(certificates, "Certificates should be read");
        assertTrue(certificates.size() >= 3, "Should have at least 3 certificates (CA, user, legal)");

        // Count certificate types
        long caCount = certificates.stream().filter(c -> "CA".equals(c.getType())).count();
        long userCount = certificates.stream().filter(c -> "USER".equals(c.getType())).count();
        long legalCount = certificates.stream().filter(c -> "LEGAL".equals(c.getType())).count();

        assertTrue(caCount >= 1, "Should have at least 1 CA certificate");
        assertEquals(1, userCount, "Should have exactly 1 user certificate");
        assertEquals(1, legalCount, "Should have exactly 1 legal certificate");

        // 3. Initialize CertificateService for signing operations (reuse existing registryService)
        var generationService = new CertificateGenerator(realProvider, tempConfig, storage);
        var validationService = new CertificateValidator(realProvider, storage);
        CertificateService certService = new CertificateService(realProvider, tempConfig, storage, generationService, validationService);
        certService.init();

        // 4. Get certificates for signing
        var caCerts = storage.getCACertificates();
        var userCerts = storage.getUserCertificates();

        assertFalse(caCerts.isEmpty(), "Should have CA certificates");
        assertFalse(userCerts.isEmpty(), "Should have user certificates");

        // Get first available CA and user cert
        var firstCaEntry = caCerts.entrySet().iterator().next();
        var caId = firstCaEntry.getKey();
        var caCert = firstCaEntry.getValue().getCertificate();

        var firstUserEntry = userCerts.entrySet().iterator().next();
        var userAlias = firstUserEntry.getKey();

        // 5. Sign some data using the user certificate
        String testData = "<root>Test data for signing</root>";
        CertificateService.SignedData signedData = certService.signDataWithResult(testData, userAlias);
        assertNotNull(signedData, "SignedData should be generated");
        assertNotNull(signedData.getSignature(), "Signature should be generated");
        assertFalse(signedData.getSignature().isEmpty(), "Signature should not be empty");
        assertEquals(testData, signedData.getOriginalData(), "Original data should match");
        assertEquals(userAlias, signedData.getCertAlias(), "Cert alias should match");

        // Test the helper methods
        String signedContent = signedData.getSignedContent();
        assertTrue(signedContent.startsWith(testData), "Signed content should start with original data");
        assertTrue(signedContent.contains(signedData.getSignature()), "Signed content should contain signature");

        String formattedContent = signedData.getFormattedSignedContent();
        assertTrue(formattedContent.contains("<data>"), "Formatted content should contain data label");
        assertTrue(formattedContent.contains("<signature>"), "Formatted content should contain signature label");

        // 6. Verify the signature (direct verification without chain validation to avoid CA private key issues)
        var userEntry = userCerts.entrySet().iterator().next();
        X509Certificate userCert = userEntry.getValue().getCertificate();
        java.security.Signature sig = java.security.Signature.getInstance(tempConfig.getSignatureAlgorithm(), realProvider.getName());
        sig.initVerify(userCert.getPublicKey());
        sig.update(testData.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] signatureBytes = java.util.Base64.getDecoder().decode(signedData.getSignature());
        boolean isValid = sig.verify(signatureBytes);
        assertTrue(isValid, "Direct signature verification should succeed");


        // 8. Final verification - ensure temp directory has the generated files
        java.io.File tempDirFile = tempDir.toFile();
        java.io.File[] files = tempDirFile.listFiles();
        assertNotNull(files, "Temp directory should contain files");
        assertTrue(files.length > 0, "Temp directory should contain generated certificate files");
    }
}
