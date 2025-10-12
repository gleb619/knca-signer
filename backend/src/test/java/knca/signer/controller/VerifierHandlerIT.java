package knca.signer.controller;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
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
import org.junit.jupiter.api.extension.ExtendWith;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for VerifierHandler HTTP endpoints
 */
@ExtendWith(VertxExtension.class)
public class VerifierHandlerIT {

    private CertificateService certificateService;
    private VerifierHandler signingHandler;
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
        var registryService = new CertificateStorage(new CertificateStorage.Storage());
        var generationService = new CertificateGenerator(realProvider, config, registryService);
        var validationService = new CertificateValidator(realProvider, registryService);
        certificateService = new CertificateService(realProvider, config, registryService, generationService, validationService).init();
        System.out.println("Using real CertificateService for integration tests");

        // Ensure user and legal certificates are generated
        certificateService.generateUserCertificate("default");
        certificateService.generateLegalEntityCertificate("default");

        signingHandler = new VerifierHandler(certificateService);

        // Set up routes
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        // Signing operations
        router.post("/sign").handler(signingHandler.handleSignData());

        // XML validation
        router.post("/validate/xml").handler(signingHandler.handleValidateXml());

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
    void testSignData(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject signRequest = new JsonObject()
                .put("data", "test data to sign")
                .put("certAlias", "user");

        client.request(HttpMethod.POST, serverPort, "localhost", "/sign")
                .compose(req -> req.send(signRequest.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertNotNull(json.getString("signature"));
                            assertEquals("user", json.getString("certAlias"));
                            assertEquals("SHA256withRSA", json.getString("algorithm"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }



    @Test
    void testSignDataWithInvalidCertificate(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("data", "test data")
                .put("certAlias", "nonexistent");

        client.request(HttpMethod.POST, serverPort, "localhost", "/sign")
                .compose(req -> req.send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(404, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertEquals("Unknown certificate alias: nonexistent", json.getString("error"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testSignDataWithMissingData(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject(); // Missing data field

        client.request(HttpMethod.POST, serverPort, "localhost", "/sign")
                .compose(req -> req.send(requestBody.encode()))
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
    void testValidateXmlWithInvalidXml(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "<invalid>xml<content>");

        client.request(HttpMethod.POST, serverPort, "localhost", "/validate/xml")
                .compose(req -> req.send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        // Should return 200 with valid=false for invalid XML
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertFalse(json.getBoolean("valid"));
                            assertEquals("XML signature is invalid", json.getString("message"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlWithMissingXml(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject(); // Missing xml field

        client.request(HttpMethod.POST, serverPort, "localhost", "/validate/xml")
                .compose(req -> req.send(requestBody.encode()))
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
    void testValidateXmlWithValidationFlags(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        JsonObject requestBody = new JsonObject()
                .put("xml", "<invalid>xml<content>")
                .put("checkKalkanProvider", true)
                .put("checkData", false)
                .put("checkTime", false)
                .put("checkIinInCert", false)
                .put("checkIinInSign", false)
                .put("checkCertificateChain", false);

        client.request(HttpMethod.POST, serverPort, "localhost", "/validate/xml")
                .compose(req -> req.send(requestBody.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        // Should return 200 with detailed result
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            assertFalse(json.getBoolean("valid"));
                            assertNotNull(json.getString("message"));
                            assertNotNull(json.getJsonObject("details"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    @Test
    void testValidateXmlWithPublicKeyCheck(Vertx vertx, VertxTestContext testContext) throws Exception {
        HttpClient client = vertx.createHttpClient();

        // Generate a valid XML with signature first
        // This is a simplified test - in practice you'd need a properly signed XML
        String xmlContent = "<xml>test content</xml>";

        JsonObject requestWithoutPublicKey = new JsonObject()
                .put("xml", xmlContent);

        // Test without public key
        client.request(HttpMethod.POST, serverPort, "localhost", "/validate/xml")
                .compose(req -> req.send(requestWithoutPublicKey.encode()))
                .onComplete(testContext.succeeding(response -> {
                    testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                    });

                    response.body().onComplete(testContext.succeeding(buffer -> {
                        testContext.verify(() -> {
                            JsonObject json = new JsonObject(buffer.toString());
                            // Should still have a result (might be invalid due to no signature)
                            assertNotNull(json.getBoolean("valid"));
                            assertNotNull(json.getString("message"));
                        });
                        testContext.completeNow();
                    }));
                }));
    }

    private List<String> getParameterTypeNames(Class<?>[] paramTypes) {
        List<String> names = new ArrayList<>();
        for (Class<?> paramType : paramTypes) {
            names.add(paramType.getName());
        }
        return names;
    }
}
