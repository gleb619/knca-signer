package knca.signer;

import knca.signer.config.ApplicationConfig;
import knca.signer.controller.VerifierHandler.XmlValidationRequest;
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
import java.util.Base64;

import static knca.signer.kalkan.KalkanConstants.KeyPurposeId.id_kp_emailProtection;
import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class MainTest {

    private static final String USER_TYPE = "user";
    private static final String LEGAL_TYPE = "legal";

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
                tempDir + "/ca-default.crt",
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
    public void testFullCertificateAndXmlWorkflow() throws Exception {
        // Generate certificates
        generateCertificates();

        // Test XML signing and validation for user certificates
        testXmlWorkflowForCertificateType(USER_TYPE, "User");

        // Test XML signing and validation for legal certificates
        testXmlWorkflowForCertificateType(LEGAL_TYPE, "Legal");
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

        // Validate XML signature with full verification flow
        verifyXmlSign(signedXml, certType, certTypeName, certAlias);
    }

    /**
     * Get the first available certificate alias of the specified type
     */
    private String getCertificateAlias(CertificateStorage storage, String certType) {
        return switch (certType) {
            case USER_TYPE -> {
                var userCerts = storage.getUserCertificates();
                assertFalse(userCerts.isEmpty(), "Should have user certificates");
                yield userCerts.keySet().iterator().next();
            }
            case LEGAL_TYPE -> {
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
        String xmlData = "<root><message>Test XML signing for %s certificate</message></root>".formatted(certTypeName);

        String signedXml = certService.signXml(xmlData, certAlias);
        assertNotNull(signedXml, "Signed XML should be generated");
        assertTrue(signedXml.contains("Signature"), "Signed XML should contain signature element");
        assertTrue(signedXml.contains("Test XML signing for " + certTypeName), "Signed XML should contain original data");
        assertTrue(signedXml.length() > xmlData.length(), "Signed XML should be longer than original");
        assertTrue(signedXml.contains("X509Certificate"), "Signed XML should contain X509Certificate");

        return signedXml;
    }

    /**
     * Validate XML signature with full verification flow
     */
    private void verifyXmlSign(String signedXml, String certType, String certTypeName, String certAlias) throws Exception {
        // Create XML validation request with full checks enabled
        var xmlValidationRequest = new XmlValidationRequest();
        xmlValidationRequest.setXml(signedXml);
        xmlValidationRequest.setCheckSignature(true);
        xmlValidationRequest.setCheckKncaProvider(true);
        xmlValidationRequest.setCheckCertificateChain(true);
        xmlValidationRequest.setCheckIinInCert(true);
        xmlValidationRequest.setCheckPublicKey(true);
        xmlValidationRequest.setCheckExtendedKeyUsage(true);

        // Extract public key directly from storage using certificate alias
        String publicKey = extractPublicKeyFromStorage(storage, certAlias, certType);
        xmlValidationRequest.setPublicKey(publicKey);

        // Set extended key usage OIDs (default for knca-signer certificates is email protection)
        xmlValidationRequest.setExtendedKeyUsageOids(id_kp_emailProtection);

        // Set checks based on certificate type
        if (LEGAL_TYPE.equals(certType)) {
            // For legal certificates, enable all applicable checks including BIN and signature validation
            xmlValidationRequest.setCheckBinInCert(true);
            // Set expected BIN from certificate data
            var certData = storage.getLegalCertificates().get(certAlias);
            if (certData != null && certData.getBin() != null) {
                xmlValidationRequest.setExpectedBin(certData.getBin());
            }
        } else {
            // For user certificates, omit BIN checks but enable all other signature validations
            xmlValidationRequest.setCheckBinInCert(false);
        }

        // Set expected IIN from certificate data for IIN check
        var certData = switch (certType) {
            case USER_TYPE -> storage.getUserCertificates().get(certAlias);
            case LEGAL_TYPE -> storage.getLegalCertificates().get(certAlias);
            default -> null;
        };
        if (certData != null && certData.getIin() != null) {
            xmlValidationRequest.setExpectedIin(certData.getIin());
        }

        // Perform full XML validation
        CertificateService.ValidationResult result = validator.validateXmlSignature(xmlValidationRequest);

        assertTrue(result.isValid(),
                "%s certificate XML validation should pass. Code: %s, Message: %s".formatted(certTypeName, result.getCode(), result.getMessage()));
    }

    /**
     * Extract the public key from certificate storage using alias and return it as PEM formatted string
     */
    private String extractPublicKeyFromStorage(CertificateStorage storage, String certAlias, String certType) throws Exception {
        // Get certificate directly from storage
        var certData = switch (certType) {
            case USER_TYPE -> storage.getUserCertificates().get(certAlias);
            case LEGAL_TYPE -> storage.getLegalCertificates().get(certAlias);
            default -> throw new IllegalArgumentException("Unknown certificate type: " + certType);
        };

        if (certData == null) {
            throw new Exception("Certificate not found in storage: " + certAlias);
        }

        // Extract public key and format as PEM
        byte[] publicKeyBytes = certData.getCertificate().getPublicKey().getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(publicKeyBytes);
        return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----".formatted(base64Key);
    }

}
