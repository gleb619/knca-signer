package knca.signer.controller;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import knca.signer.service.CertificateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CI tests for VerifierHandler using mocked services (no real Kalkan dependencies).
 * Runs when kalkanAllowed=false to test VerifierHandler logic without real crypto operations.
 */
@ExtendWith(VertxExtension.class)
@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "false")
public class VerifierHandlerCITest {

    @Mock
    private CertificateService certificateService;

    private VerifierHandler verifierHandler;
    private int serverPort;

    @BeforeEach
    void setUp(Vertx vertx, VertxTestContext testContext) {
        MockitoAnnotations.openMocks(this);

        // Create handler with mocked service
        verifierHandler = new VerifierHandler(certificateService);

        // Setup mock responses
        setupMockCertificateService();

        // Set up routes
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        // XML operations
        router.post("/xml/sign").handler(verifierHandler.handleSignData());
        router.post("/xml/validate").handler(verifierHandler.handleValidateXml());

        // Start server on a random available port
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(0)
                .onComplete(testContext.succeeding(server -> {
                    serverPort = server.actualPort();
                    System.out.println("VerifierHandler CI test server started on port: " + serverPort);
                    testContext.completeNow();
                }));
    }

    private void setupMockCertificateService() {
        try {
            // Mock XML operations
            when(certificateService.signXml(anyString(), anyString()))
                    .thenReturn("<signed-xml>test</signed-xml>");

            when(certificateService.validateXmlSignature(any()))
                    .thenReturn(new CertificateService.ValidationResult(true, "VALID", "Mock validation successful", java.util.Collections.emptyList()));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }
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
                            assertEquals("XMLDSig", json.getString("algorithm"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testSignXmlEndpointWithDefaultCertAlias(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("data", "<test>data</test>");
        // No certAlias provided, should default to "user"

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/sign")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        verify(certificateService).signXml(anyString(), eq("user"));
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertNotNull(json.getString("signedXml"));
                            assertEquals("user", json.getString("certAlias"));
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
        // Missing data field

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
    void testSignXmlEndpointWithEmptyData(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("data", "")
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
    void testSignXmlEndpointWithInvalidCertAlias(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        try {
            // Mock certificate service to throw IllegalArgumentException for invalid alias
            when(certificateService.signXml(anyString(), eq("invalid-alias")))
                    .thenThrow(new IllegalArgumentException("Unknown certificate alias: invalid-alias"));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }

        JsonObject requestBody = new JsonObject()
                .put("data", "<test>data</test>")
                .put("certAlias", "invalid-alias");

        client.request(HttpMethod.POST, serverPort, "localhost", "/xml/sign")
                .compose(req -> req.putHeader("content-type", "application/json").send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(404, response.statusCode());
                        verify(certificateService).signXml(anyString(), eq("invalid-alias"));
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("Unknown certificate alias: invalid-alias", json.getString("error"));
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
                            assertEquals("Mock validation successful", json.getString("message"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlEndpointWithValidationFailure(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        try {
            // Mock validation failure
            when(certificateService.validateXmlSignature(any()))
                    .thenReturn(new CertificateService.ValidationResult(false, "INVALID", "Validation failed", java.util.Collections.emptyList()));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }

        JsonObject requestBody = new JsonObject()
                .put("xml", "<invalid-xml>test</invalid-xml>");

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
                            assertFalse(json.getBoolean("valid"));
                            assertEquals("Validation failed", json.getString("message"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlEndpointWithMissingXml(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject();
        // Missing xml field

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

    @Test
    void testValidateXmlEndpointWithEmptyXml(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "");

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

    @Test
    void testValidateXmlEndpointWithValidationOptions(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "<signed-xml>test</signed-xml>")
                .put("checkSignature", true)
                .put("checkKncaProvider", false)
                .put("checkIinInCert", true)
                .put("checkBinInCert", false)
                .put("checkCertificateChain", true)
                .put("checkPublicKey", false)
                .put("checkExtendedKeyUsage", true)
                .put("extendedKeyUsageOids", "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")
                .put("expectedIin", "123456789012")
                .put("expectedBin", null);

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
    void testValidateXmlEndpointWithPublicKey(Vertx vertx, VertxTestContext testContext) {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "<signed-xml>test</signed-xml>")
                .put("publicKey", "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3...") // Mock base64 public key
                .put("caPem", "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"); // Mock base64 CA PEM

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
}
