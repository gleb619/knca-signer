package knca.signer.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.jackson.DatabindCodec;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * CI tests for controllers using mocked services (no real Kalkan dependencies).
 * Runs when kalkanAllowed=false to test controller logic without real crypto operations.
 */
@ExtendWith(VertxExtension.class)
@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "false")
public class ControllerCITest {

    @Mock
    private CertificateService certificateService;

    @Mock
    private CertificateStorage certificateStorage;

    private CertificatorHandler certificatorHandler;
    private VerifierHandler verifierHandler;
    private int serverPort;

    @BeforeEach
    void setUp(Vertx vertx, VertxTestContext testContext) {
        MockitoAnnotations.openMocks(this);

        // Configure DatabindCodec for LocalDateTime serialization (same as BeanFactory)
        DatabindCodec.mapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        // Create handlers with mocked services
        certificatorHandler = new CertificatorHandler(certificateService, certificateStorage);
        verifierHandler = new VerifierHandler(certificateService);

        // Setup mock certificate service responses
        setupMockCertificateService();

        // Set up routes
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        // Certificate operations
        router.get("/certificates/ca").handler(certificatorHandler.handleGetCACertificate());
        router.get("/certificates/user").handler(certificatorHandler.handleGetUserCertificate());
        router.get("/certificates/legal").handler(certificatorHandler.handleGetLegalCertificate());
        router.post("/certificates/generate/ca").handler(certificatorHandler.handleGenerateCACertificate());
        router.post("/certificates/generate/user").handler(certificatorHandler.handleGenerateUserCertificate());
        router.post("/certificates/generate/legal").handler(certificatorHandler.handleGenerateLegalCertificate());

        // XML operations
        router.post("/xml/sign").handler(verifierHandler.handleSignData());
        router.post("/xml/validate").handler(verifierHandler.handleValidateXml());

        // Start server on a random available port
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(0)
                .onComplete(testContext.succeeding(server -> {
                    serverPort = server.actualPort();
                    System.out.println("CI test server started on port: " + serverPort);
                    testContext.completeNow();
                }));
    }

    private void setupMockCertificateService() {
        try {
            // Create mock certificate data
            CertificateService.CertificateData caData = createMockCertificateData("CA");
            CertificateService.CertificateData userData = createMockCertificateData("USER");
            CertificateService.CertificateData legalData = createMockCertificateData("LEGAL");

            // Mock certificate generation responses
            when(certificateService.generateCACertificate(any()))
                    .thenReturn(Map.entry("ca-test", createMockCertificateResult()));

            when(certificateService.generateUserCertificate(any()))
                    .thenReturn(Map.entry("user-test", userData));

            when(certificateService.generateLegalEntityCertificate(any()))
                    .thenReturn(Map.entry("legal-test", legalData));

            // Mock XML operations
            when(certificateService.signXml(anyString(), anyString()))
                    .thenReturn("<signed-xml>test</signed-xml>");

            when(certificateService.validateXmlSignature(any()))
                    .thenReturn(new CertificateService.ValidationResult(true, "VALID", "Mock validation successful", java.util.Collections.emptyList()));

            // Setup storage to return generated certificates
            when(certificateStorage.getCACertificates()).thenReturn(Map.of("ca-test", caData));
            when(certificateStorage.getUserCertificates()).thenReturn(Map.of("user-test", userData));
            when(certificateStorage.getLegalCertificates()).thenReturn(Map.of("legal-test", legalData));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }
    }

    private CertificateService.CertificateResult createMockCertificateResult() {
        return new CertificateService.CertificateResult(
                mock(KeyPair.class),
                mock(X509Certificate.class)
        );
    }

    private CertificateService.CertificateData createMockCertificateData(String type) throws java.security.cert.CertificateEncodingException, java.security.cert.CertificateParsingException {
        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));

        X500Principal mockIssuerDN = mock(X500Principal.class);
        when(mockIssuerDN.getName()).thenReturn("CN=Test " + type);
        when(mockCert.getIssuerDN()).thenReturn(mockIssuerDN);

        String subject;
        if ("LEGAL".equals(type)) {
            subject = "CN=Test Legal,OU=BIN,IIN=123456789012";
        } else if ("USER".equals(type)) {
            subject = "CN=Test User,IIN=123456789012";
        } else {
            subject = "CN=Test CA";
        }
        X500Principal mockSubjectDN = mock(X500Principal.class);
        when(mockSubjectDN.getName()).thenReturn(subject);
        when(mockCert.getSubjectDN()).thenReturn(mockSubjectDN);

        when(mockCert.getVersion()).thenReturn(3);
        when(mockCert.getBasicConstraints()).thenReturn(type.equals("CA") ? 0 : -1);
        when(mockCert.getKeyUsage()).thenReturn(null);
        when(mockCert.getCriticalExtensionOIDs()).thenReturn(null);
        when(mockCert.getNonCriticalExtensionOIDs()).thenReturn(null);
        when(mockCert.getExtendedKeyUsage()).thenReturn(null);
        doAnswer(invocation -> new byte[0]).when(mockCert).getEncoded();
        when(mockCert.getNotBefore()).thenReturn(new Date());
        when(mockCert.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
        RSAPublicKey mockKey = mock(RSAPublicKey.class);
        when(mockKey.getAlgorithm()).thenReturn("RSA");
        BigInteger modulus = new BigInteger("1234567890123456789012345678901234567890");
        when(mockKey.getModulus()).thenReturn(modulus);
        when(mockCert.getPublicKey()).thenReturn(mockKey);
        when(mockCert.getSigAlgOID()).thenReturn("1.2.840.113549.1.1.11");
        when(mockCert.getSigAlgName()).thenReturn("SHA256withRSA");

        return new CertificateService.CertificateData(
                "test@example.com",
                "123456789012",
                type.equals("LEGAL") ? "123456789" : null,
                "test-ca",
                mockCert
        );
    }

    @Test
    void testGetCACertificatesEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.GET, serverPort, "localhost", "/certificates/ca")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });
                    testContext.completeNow();
                }));
    }

    @Test
    void testGetUserCertificatesEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.GET, serverPort, "localhost", "/certificates/user")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertNotNull(json);
                            assertTrue(json.containsKey("certificates"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGenerateCACertificateEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/ca")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).generateCACertificate(any());
                    });
                    testContext.completeNow();
                }));
    }

    @Test
    void testGenerateUserCertificateEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/user")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).generateUserCertificate(any());
                    });
                    testContext.completeNow();
                }));
    }

    @Test
    void testGenerateLegalCertificateEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/legal")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).generateLegalEntityCertificate(any());
                    });
                    testContext.completeNow();
                }));
    }

    @Test
    void testSignXmlEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("data", "<test>data</test>")
                .put("certAlias", "test-cert");

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/sign")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).signXml(anyString(), anyString());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertNotNull(json.getString("signedXml"));
                            assertEquals("test-cert", json.getString("certAlias"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testSignXmlEndpointWithMissingData(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("certAlias", "test-cert");

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/sign")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(400, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("Data is required", json.getString("error"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlEndpoint(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "<signed-xml>test</signed-xml>");

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/validate")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).validateXmlSignature(any());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertTrue(json.getBoolean("valid"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlEndpointWithMissingXml(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject();

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/validate")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(400, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("XML content is required", json.getString("error"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }
}
