package knca.signer.example;

import io.vertx.core.Vertx;
import knca.signer.config.ApplicationConfig;
import knca.signer.config.BeanFactory;
import knca.signer.service.CertificateService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
class SignerTest {

    private BeanFactory beanFactory;
    private CertificateService certificateService;
    private Vertx vertx;
    private ApplicationConfig.CertificateConfig config;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        // Create certificate config (same as MainTest)
        config = new ApplicationConfig.CertificateConfig(
                "in-memory",
                3,
                2,
                tempDir + "/certs/",
                tempDir + "/certs/ca-default.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );

        // Create full application config
        ApplicationConfig appConfig = ApplicationConfig.builder()
                .http(new ApplicationConfig.HttpConfig(8080, "0.0.0.0"))
                .cors(new ApplicationConfig.CorsConfig("*", java.util.Arrays.asList("GET", "POST", "PUT", "DELETE"), java.util.Arrays.asList("Content-Type", "Authorization")))
                .logging(new ApplicationConfig.LoggingConfig("INFO"))
                .certificate(config)
                .staticConfig(new ApplicationConfig.StaticConfig("static"))
                .build();

        // Create Vertx for BeanFactory
        vertx = Vertx.vertx();

        // Create and initialize bean factory
        beanFactory = new BeanFactory(vertx, appConfig);
        beanFactory.init();

        // Get CertificateService from bean factory
        certificateService = beanFactory.getCertificateService();

        // Generate certificates for testing (same as other tests)
        certificateService.generateCACertificate("default");
        certificateService.generateUserCertificate("default");
        certificateService.generateLegalEntityCertificate("default");

        assertNotNull(certificateService, "CertificateService should be initialized");
    }

    @AfterEach
    void tearDown() {
        if (vertx != null) {
            vertx.close();
        }
    }

    @Test
    public void testBeanFactoryProvidesCertificateService() {
        assertNotNull(certificateService, "CertificateService should be available from BeanFactory");
    }

    @Test
    public void testXmlSigningWithBeanFactory() throws Exception {
        // Create simple XML content to sign
        String xmlContent = "<test><message>Hello World</message></test>";

        // Sign the XML using CertificateService from BeanFactory
        String signedXml = certificateService.signXml(xmlContent, "user");

        // Verify the signed XML
        assertNotNull(signedXml, "Signed XML should not be null");
        assertTrue(signedXml.contains("Signature"), "Signed XML should contain signature element");
        assertTrue(signedXml.contains("<message>Hello World</message>"), "Signed XML should contain original content");
        assertTrue(signedXml.length() > xmlContent.length(), "Signed XML should be longer than original");
    }

    @Test
    public void testDataSigningWithBeanFactory() throws Exception {
        String testData = "Hello World Data";
        String certAlias = "user";

        // Sign the data using CertificateService from BeanFactory
        CertificateService.SignedData signedData = certificateService.signDataWithResult(testData, certAlias);

        // Verify the signed data
        assertNotNull(signedData, "Signed data should not be null");
        assertEquals(testData, signedData.getOriginalData(), "Original data should match");
        assertEquals(certAlias, signedData.getCertAlias(), "Certificate alias should match");
        assertNotNull(signedData.getSignature(), "Signature should be present");
        assertFalse(signedData.getSignature().isEmpty(), "Signature should not be empty");
    }

    @Test
    public void testSignedDataFormatting() throws Exception {
        String originalData = "<xml>test</xml>";
        String signature = "dGVzdCBzaWduYXR1cmU="; // Base64 for "test signature"
        String certAlias = "test-alias";

        CertificateService.SignedData signedData = new CertificateService.SignedData(originalData, signature, certAlias);

        // Test formatted content
        String formatted = signedData.getFormattedSignedContent();
        assertTrue(formatted.contains("<data>"), "Should contain data element");
        assertTrue(formatted.contains("<signature>"), "Should contain signature element");
        assertTrue(formatted.contains("<alias>"), "Should contain alias element");
        assertTrue(formatted.contains("test-alias"), "Should contain the actual alias");
    }

    @Test
    public void testCertificateRetrievalFromBeanFactory() {
        // Test that we can retrieve certificates through the service
        assertDoesNotThrow(() -> {
            certificateService.getCertificate("user");
        }, "Should be able to retrieve user certificate");

        assertDoesNotThrow(() -> {
            certificateService.getCertificate("legal");
        }, "Should be able to retrieve legal certificate");
    }
}
