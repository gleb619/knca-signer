package knca.signer.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.jackson.DatabindCodec;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import knca.signer.service.CertificateValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for CertificatorHandler HTTP endpoints
 */
@ExtendWith(VertxExtension.class)
@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "true")
public class CertificatorHandlerIT {

    private CertificateService certificateService;
    private CertificatorHandler certificateHandler;
    private int serverPort;

    private Path tempDir;

    @BeforeEach
    void setUp(Vertx vertx, VertxTestContext testContext) throws Exception {
        // Create a temporary directory for certificate storage
        tempDir = Files.createTempDirectory("knca-signer-test-");

        // Create config for CertificateService
        java.security.Provider realProvider = knca.signer.kalkan.KalkanRegistry.loadRealKalkanProvider();
        knca.signer.config.ApplicationConfig.CertificateConfig config = new knca.signer.config.ApplicationConfig.CertificateConfig(
                "certs/",
                "certs/ca.crt",
                2048,
                "RSA",
                "1.2.840.113549.1.1.11",
                "123456",
                10,
                1
        );

        // Create real CertificateService - no mocking
        var storageService = new CertificateStorage(new CertificateStorage.Storage());
        var generationService = new CertificateGenerator(realProvider, config, storageService);
        var validationService = new CertificateValidator(realProvider, storageService);
        certificateService = new CertificateService(realProvider, config, storageService, generationService, validationService)
                .init();
        System.out.println("Using real CertificateService for integration tests");

        DatabindCodec.mapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        certificateHandler = new CertificatorHandler(certificateService, storageService);

        // Set up routes
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        // Certificate operations - split endpoints
        router.get("/certificates/ca").handler(certificateHandler.handleGetCACertificate());
        router.get("/certificates/user").handler(certificateHandler.handleGetUserCertificate());
        router.get("/certificates/legal").handler(certificateHandler.handleGetLegalCertificate());
        router.get("/certificates/filesystem").handler(certificateHandler.handleGetFilesystemCertificates());
        router.post("/certificates/generate/ca").handler(certificateHandler.handleGenerateCACertificate());
        router.post("/certificates/generate/user").handler(certificateHandler.handleGenerateUserCertificate());
        router.post("/certificates/generate/legal").handler(certificateHandler.handleGenerateLegalCertificate());

        // Start server on a random available port
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(0) // Use 0 to get a random available port
                .onComplete(testContext.succeeding(server -> {
                    serverPort = server.actualPort();
                    System.out.println("Integration test server started on port: " + serverPort);
                    testContext.completeNow();
                }));
    }

    @AfterEach
    void tearDown() throws Exception {
        // Clean up temporary directory
        if (tempDir != null && Files.exists(tempDir)) {
            // Delete all files in the temp directory
            Files.walk(tempDir)
                    .filter(Files::isRegularFile)
                    .forEach(file -> {
                        try {
                            Files.delete(file);
                        } catch (Exception e) {
                            System.err.println("Failed to delete temp file: " + file + " - " + e.getMessage());
                        }
                    });
            // Delete the directory itself
            try {
                Files.delete(tempDir);
            } catch (Exception e) {
                System.err.println("Failed to delete temp directory: " + tempDir + " - " + e.getMessage());
            }
        }
    }

    @Test
    void testGenerateUserCertificate(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/user")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("user", json.getString("type"));
                            String alias = json.getString("alias");
                            assertNotNull(alias);
                            assertTrue(alias.startsWith("user-"));
                            assertNotNull(json.getString("email"));
                            assertNotNull(json.getString("iin"));
                            assertNotNull(json.getString("subject"));
                            assertTrue(json.getBoolean("generated"));
                            assertEquals("default", json.getString("caId"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGenerateLegalEntityCertificate(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/legal")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("legal", json.getString("type"));
                            String alias = json.getString("alias");
                            assertNotNull(alias);
                            assertTrue(alias.startsWith("legal-"));
                            assertNotNull(json.getString("email"));
                            assertNotNull(json.getString("iin"));
                            assertNotNull(json.getString("bin"));
                            assertNotNull(json.getString("subject"));
                            assertTrue(json.getBoolean("generated"));
                            assertEquals("default", json.getString("caId"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGenerateCACertificate(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/ca?alias=test-ca")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("ca", json.getString("type"));
                            String alias = json.getString("alias");
                            assertNotNull(alias);
                            assertTrue(alias.startsWith("ca-") || alias.equals("test-ca"));
                            assertNotNull(json.getString("subject"));
                            assertTrue(json.getBoolean("generated"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGenerateUserCertificateForSpecificCA(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        // First generate a custom CA
        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/ca?alias=custom-ca")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(caResponse -> {
                    testContext.verify(() -> {
                        assertEquals(200, caResponse.statusCode());
                    });

                    // Now generate user certificate for this CA
                    client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/user")
                            .compose(req -> req.putHeader("content-type", "application/json").send(new JsonObject().put("caId", "custom-ca").encode()))
                            .onComplete(testContext.succeeding(userResponse -> {
                                testContext.verify(() -> {
                                    assertEquals(200, userResponse.statusCode());
                                });

                                userResponse.body().onComplete(testContext.succeeding(buffer -> {
                                    testContext.verify(() -> {
                                        JsonObject json = new JsonObject(buffer.toString());
                                        assertEquals("user", json.getString("type"));
                                        assertEquals("custom-ca", json.getString("caId"));
                                        assertTrue(json.getBoolean("generated"));
                                    });
                                    testContext.completeNow();
                                }));
                            }));
                }));
    }

    @Test
    void testGenerateLegalCertificateForSpecificCA(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        // Generate legal certificate for default CA
        client.request(HttpMethod.POST, serverPort, "localhost", "/certificates/generate/legal")
                .compose(req -> req.putHeader("content-type", "application/json").send(new JsonObject().put("caId", "default").encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("legal", json.getString("type"));
                            assertEquals("default", json.getString("caId"));
                            assertTrue(json.getBoolean("generated"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGetCertificatesForCA(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.GET, serverPort, "localhost", "/certificates/user?caId=default")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            // Should contain certificates array
                            assertNotNull(json);
                            assertTrue(json.containsKey("certificates"));
                            assertInstanceOf(JsonArray.class, json.getJsonArray("certificates"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testGetFilesystemCertificates(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        client.request(HttpMethod.GET, serverPort, "localhost", "/certificates/filesystem")
                .compose(HttpClientRequest::send)
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            // Should contain certificates array from filesystem
                            assertNotNull(json);
                            assertTrue(json.containsKey("certificates"));
                            JsonArray certificates = json.getJsonArray("certificates");
                            assertNotNull(certificates);
                            assertInstanceOf(JsonArray.class, certificates);

                            // Verify at least one certificate exists (generated during service initialization)
                            assertTrue(certificates.size() >= 1, "Should have at least one certificate");

                            // Check first certificate structure
                            JsonObject firstCert = certificates.getJsonObject(0);
                            assertNotNull(firstCert.getString("type"));
                            assertNotNull(firstCert.getString("filename"));
                            assertNotNull(firstCert.getString("serialNumber"));
                            assertNotNull(firstCert.getString("issuer"));
                            assertNotNull(firstCert.getString("subject"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

}
