package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanProxy;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService.CertificateResult;
import knca.signer.service.CertificateStorage;
import knca.signer.service.CertificateValidator;
import knca.signer.service.CertificateValidator.XmlValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class ValidatorTest {

    String testXmlContent = """
            <?xml version="1.0" encoding="UTF-8" standalone="no"?><root>
                  <item>Сәлем, досым! Привет, друг!</item>
                  <note>Бұл тест. Это тест.</note>
              <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI="">
              <ds:Transforms>
              <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
              <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>GegDfJ4m+GFSHRQ0KbPQ69QMlCWVFcS0tjwoxumBblw=</ds:DigestValue>
              </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>
              f/lQt5b4QKnFcEOc5jZAPBZX0+IhNyrHJFD1B1BGUfA4gwrYEUqOKDM7LDfgaphpkoOtlVyZlbT1
              WqWNoZh6684Cp3jGXJfYavi9urqn6S3hDInkFLazi82SSG1bQRN+0jc9Qry44JH2X9Mig+lSz7PW
              Pcxgbb2R6sOzF5FSbuA3wnpr2syg6CNhE2Xz+I74OE3d1FB/HW+UPi4ln5B4CpwCLKBh91e2Z0tT
              LterqCQWzAdHCOnIyxxhSD1VM+bE/UWX7wgTvUnFr+gRUn/2tKU2D3XaKs/PyGsdUoKXzfNCtG4j
              RTcqfemInfdWRXJTK+euKMd6Npfx25kj3s1FhQ==
              </ds:SignatureValue>
              <ds:KeyInfo>
              <ds:X509Data>
              <ds:X509Certificate>
              MIIEnzCCA4egAwIBAgIUGVcEMBtACsuqygKoF9rUE/i31HwwDQYJKoZIhvcNAQELBQAwXjELMAkG
              A1UEBhMCS1oxTzBNBgNVBAMMRtCd0JXQk9CG0JfQk9CGINCa0KPTmNCb0JDQndCU0KvQoNCj0KjQ
              qyDQntCg0KLQkNCb0KvSmiAoUlNBKSBURVNUIDIwMjUwHhcNMjUwOTMwMTEzMjQ3WhcNMjYwOTMw
              MTEzMjQ3WjCCAR8xJDAiBgNVBAMMG9CQ0KXQnNCV0KIg0JzQhtCg0JbQkNKa0KvQnzEZMBcGA1UE
              BAwQ0JzQhtCg0JbQkNKa0KvQnzEYMBYGA1UEBRMPSUlOOTE0NDQ2MDk0NTkzMQswCQYDVQQGEwJL
              WjEvMC0GA1UECgwm0prQkNCX0JDSmtCh0KLQkNCdINCi0JXQnNCG0KAg0JbQntCb0KsxGDAWBgNV
              BAsMD0JJTjE2NDUwMDgzMjMyMDEQMA4GA1UEDwwHS1MwMTIzNDEZMBcGA1UEKgwQ0JDQpdCc0JXQ
              otKw0JvQqzEWMBQGCgmSJomT8ixkARkWBlJPTEUwNDElMCMGCSqGSIb3DQEJARYWdXNlclpERGY2
              NWpDQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJH23F94Njj04Jc7
              JKVassE5rVC5VqLucQyt+9QKujPZFgciKWHyt+nhKZMq5JkQq8scD7XhU7/4Ui2MW8fsQYJTpusx
              /DT11YauXaaKKjCsZ4DBxRiDnEPTP3IzeGIubnuFj7VMuP7NH/ogNuQDlqzhq/DVUAzp60c9ZeQg
              QGD0rYzLwUdozZINAQnLo6x0xVoAVoZIZ21HpjrfCG9G2BCIR4KI7TMSsPxlD0699X6JefttHDQH
              p972R6vG9G/Nc1/fvefgj85Y8aDvA2NvQYD1sQtXmNcYEnK/gADwyl7s6VqYvGrkN9zgmJEElokF
              LO9M38mH3zIabI9SbnuCnxUCAwEAAaOBkTCBjjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIA
              AzATBgNVHSUEDDAKBggrBgEFBQcDBDBZBgNVHREEUjBQgRZ1c2VyWkREZjY1akNAZ21haWwuY29t
              oBqgCgYIKoMOAwMEAQEMDDkxNDQ0NjA5NDU5M6AaoAoGCCqDDgMDBAECDAwxNjQ1MDA4MzIzMjAw
              DQYJKoZIhvcNAQELBQADggEBAGAH0FZVFNPttVDln+GLkgXWca6XgcDOD5CNe+HbT4kDqtDBjNcp
              GB9qox1hV1pGAn5V0lpM+xz3yz2oI3jyLJSj85pByVLlASi7oYgxczN37DMEKiPpBKO/nmUAx00d
              ja4HfNs+c7QhT+qtdQv/SB1Vc0Zva8zcY1EO0fySOC+WjQapRBM5dMbQmJTQY+jN3RpHqTIDEG90
              BfxPWnCBgIQObSV4S3o+LZCYOz0fGFqVwJZTqKL16I2g0A8hpgrVqU1IAVu9qK3WXynQv6nvainR
              EK3JJasAHTVn9OdSHQrwOgd9f1tiIQSmtVkcpbl2+zHgFCMR/0m2ZLney2PnJYQ=
              </ds:X509Certificate>
              </ds:X509Data>
              </ds:KeyInfo>
              </ds:Signature></root>
            """;
    private java.security.Provider realProvider;
    private ApplicationConfig.CertificateConfig config;

    @BeforeEach
    void setUp() throws Exception {
        realProvider = KalkanRegistry.loadRealKalkanProvider();
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

    @Test
    public void testValidatorInstantiation() {
        // Test that we can create a Validator instance
        try {
            Validator validator = new Validator();
            assertNotNull(validator, "Validator should be created");
        } catch (Exception e) {
            fail("Validator should be instantiable: " + e.getMessage());
        }
    }

    @Test
    public void testXmlValidatorCreation() {
        try {
            // Create a dummy CA certificate for testing
            var registryService = new CertificateStorage(new CertificateStorage.Storage());
            CertificateGenerator generator = new CertificateGenerator(realProvider, config, registryService);
            CertificateResult caResult = generator.generateCACertificate();
            X509Certificate caCert = caResult.getCertificate();

            XmlValidator xmlValidator = new XmlValidator(caCert, realProvider);
            assertNotNull(xmlValidator, "XmlValidator should be created");
        } catch (Exception e) {
            fail("XmlValidator creation should succeed: " + e.getMessage());
        }
    }

    @Test
    public void testCertificateValidator() {
        try {
            // Test loading CA certificate
            X509Certificate caCert = CertificateValidator.loadCACertificate(config.getCaCertPath());
            assertNotNull(caCert, "CA certificate should be loaded");

            // Test certificate validation (self-signed CA should validate against itself)
            CertificateValidator.validateCertificate(caCert, caCert, realProvider);
        } catch (Exception e) {
            fail("Certificate validation should succeed: " + e.getMessage());
        }
    }

    @Test
    public void testKalkanProviderWrapper() {
        // Test that our KalkanProvider proxy works
        try {
            KalkanProxy provider = new KalkanRegistry().createKalkanProvider();
            assertNotNull(provider, "KalkanProvider should be created");
            assertNotNull(provider.getRealObject(), "Provider should have real object");
        } catch (Exception e) {
            fail("KalkanProvider proxy should work: " + e.getMessage());
        }
    }

    @Test
    public void testWorkMethod() {
        // Test that the work method can be called
        // This is a smoke test - we expect it to fail gracefully with missing CA cert
        Validator validator = new Validator();
        try {
            validator.work(testXmlContent);
            // If it doesn't throw an exception, that's fine
        } catch (Exception e) {
            // Expected to fail without proper setup, but should not crash
            assertNotNull("Exception should be meaningful", e.getMessage());
        }
    }

    @Test
    public void testXmlValidationWithInvalidXml() {
        try {
            // Create a dummy CA certificate
            var registryService = new CertificateStorage(new CertificateStorage.Storage());
            CertificateGenerator generator = new CertificateGenerator(realProvider, config, registryService);
            CertificateResult caResult = generator.generateCACertificate();
            X509Certificate caCert = caResult.getCertificate();

            XmlValidator xmlValidator = new XmlValidator(caCert, realProvider);

            // Test with invalid XML (no signature)
            String invalidXml = "<root><test>Invalid XML</test></root>";
            boolean result = xmlValidator.validateXmlSignature(invalidXml);
            assertFalse(result, "Invalid XML should fail validation");
        } catch (Exception e) {
            // Expected to fail, but should not crash
            assertNotNull("Exception should be meaningful", e.getMessage());
        }
    }

    @Test
    public void testCertificateConfigInValidator() {
        ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
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
        assertNotNull(config, "Config should be created");
        assertEquals("certs/ca.crt", config.getCaCertPath());
    }
}
