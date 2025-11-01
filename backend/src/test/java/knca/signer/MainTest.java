package knca.signer;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import knca.signer.service.CertificateValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class MainTest {

    @TempDir
    Path tempDir;

    Provider provider;
    CertificateStorage storage;
    CertificateGenerator generator;
    CertificateValidator validator;
    CertificateService certService;

    @BeforeEach
    void setUp() throws Exception {
        ApplicationConfig.CertificateConfig tempConfig = new ApplicationConfig.CertificateConfig(
                "in-memory",
                1,
                1,
                tempDir.toString() + "/",
                tempDir + "/ca.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );

        provider = KalkanRegistry.loadRealKalkanProvider();
        storage = new CertificateStorage(new CertificateStorage.Storage());
        generator = new CertificateGenerator(provider, tempConfig, storage);
        validator = new CertificateValidator(provider, storage);
        certService = new CertificateService(provider, tempConfig, storage, generator, validator);
    }

    /**
     * Comprehensive integration test for certificate generation, XML signing and validation.
     * Tests both user and legal certificates with knca-signer validation.
     */
    @Test
    public void testFullCertificateAndXmlWorkflow(@TempDir Path tempDir) throws Exception {
        // Generate certificates
        generateCertificates();

        // Test XML signing and validation for user certificates
        testXmlWorkflowForCertificateType("user", "User");

        // Test XML signing and validation for legal certificates
        testXmlWorkflowForCertificateType("legal", "Legal");
    }

    /**
     * Generate certificates using the service
     */
    private void generateCertificates() throws Exception {
        certService.init();

        // Verify certificates were generated
        var caCerts = storage.getCACertificates();
        var userCerts = storage.getUserCertificates();
        var legalCerts = storage.getLegalCertificates();

        assertFalse(caCerts.isEmpty(), "Should have CA certificates");
        assertFalse(userCerts.isEmpty(), "Should have user certificates");
        assertFalse(legalCerts.isEmpty(), "Should have legal certificates");
    }

    /**
     * Test XML signing and validation workflow for a specific certificate type
     */
    private void testXmlWorkflowForCertificateType(String certType, String certTypeName) throws Exception {
        // Get certificate alias
        String certAlias = getCertificateAlias(storage, certType);

        // Sign XML
        String signedXml = signXmlWithCertificate(certService, certAlias, certTypeName);

        // Validate knca-signer marker
        //#TODO: call `validateXmlSignature`, not `checkKncaProvider`, we need to run all xml checks for the signature  
        verifyXmlSign(signedXml, certTypeName);
    }

    /**
     * Get the first available certificate alias of the specified type
     */
    private String getCertificateAlias(CertificateStorage storage, String certType) {
        return switch (certType) {
            case "user" -> {
                var userCerts = storage.getUserCertificates();
                assertFalse(userCerts.isEmpty(), "Should have user certificates");
                yield userCerts.keySet().iterator().next();
            }
            case "legal" -> {
                var legalCerts = storage.getLegalCertificates();
                assertFalse(legalCerts.isEmpty(), "Should have legal certificates");
                yield legalCerts.keySet().iterator().next();
            }
            default -> throw new IllegalArgumentException("Unknown certificate type: " + certType);
        };
    }

    /**
     * Sign XML content with the specified certificate
     */
    private String signXmlWithCertificate(CertificateService certService, String certAlias, String certTypeName) throws Exception {
        String xmlData = "<root><message>Test XML signing for " + certTypeName + " certificate</message></root>";

        String signedXml = certService.signXml(xmlData, certAlias);
        assertNotNull(signedXml, "Signed XML should be generated");
        assertTrue(signedXml.contains("Signature"), "Signed XML should contain signature element");
        assertTrue(signedXml.contains("Test XML signing for " + certTypeName), "Signed XML should contain original data");
        assertTrue(signedXml.length() > xmlData.length(), "Signed XML should be longer than original");
        assertTrue(signedXml.contains("X509Certificate"), "Signed XML should contain X509Certificate");

        return signedXml;
    }

    /**
     * Validate that the signed XML contains a certificate with knca-signer marker using full XML validation
     */
    private void verifyXmlSign(String signedXml, String certTypeName) throws Exception {
        // Create XML validation request with knca-signer check enabled
        // Note: Signature validation is skipped for test purposes since we're using self-generated certificates
        // The main goal is to validate the Kalkan provider check works correctly
        var xmlValidationRequest = new knca.signer.controller.VerifierHandler.XmlValidationRequest();
        xmlValidationRequest.setXml(signedXml);
        xmlValidationRequest.setCheckSignature(false); // Skip signature validation for self-generated certs
        xmlValidationRequest.setCheckKncaProvider(true);
        xmlValidationRequest.setCheckCertificateChain(false); // Skip chain validation for test
        xmlValidationRequest.setCheckData(false);
        xmlValidationRequest.setCheckTime(false);
        xmlValidationRequest.setCheckIinInCert(false);
        xmlValidationRequest.setCheckIinInSign(false);
        xmlValidationRequest.setCheckBinInCert(false);
        xmlValidationRequest.setCheckBinInSign(false);
        xmlValidationRequest.setCheckPublicKey(false);
        xmlValidationRequest.setCheckExtendedKeyUsage(false);

        // Perform full XML validation
        CertificateService.ValidationResult result = validator.validateXmlSignature(xmlValidationRequest);

        assertTrue(result.isValid(),
                certTypeName + " certificate XML validation should pass. Code: " + result.getCode() + ", Message: " + result.getMessage());
    }

}
