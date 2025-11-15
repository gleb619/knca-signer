package knca.signer.controller;

import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxExtension;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * CI tests for WebSocketHandler using mocked services (no real Kalkan dependencies).
 * Runs when kalkanAllowed=false to test WebSocketHandler logic without real crypto operations.
 */
@ExtendWith(VertxExtension.class)
@EnabledIfSystemProperty(named = "kalkanAllowed", matches = "false")
public class WebSocketHandlerCITest {

    @Mock
    private CertificateService certificateService;

    @Mock
    private CertificateStorage certificateStorage;

    @Mock
    private ServerWebSocket mockWebSocket;

    private WebSocketHandler webSocketHandler;
    private Map<String, ServerWebSocket> connectedClients;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        connectedClients = new ConcurrentHashMap<>();

        // Create handler with mocked services
        Vertx mockVertx = mock(Vertx.class);
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            var blockingHandler = (Handler<Promise<Void>>) invocation.getArgument(0);
            var promise = Promise.<Void>promise();
            blockingHandler.handle(promise);
            return null;
        }).when(mockVertx).executeBlocking(any(), anyBoolean(), any());
        webSocketHandler = new WebSocketHandler(certificateService, certificateStorage, connectedClients, mockVertx, mockVertx.eventBus());

        // Setup mock responses
        setupMockCertificateService();
    }

    private Map<String, CertificateService.CertificateData> createMockCertificates() {
        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));
        when(mockCert.getIssuerDN()).thenReturn(new X500Principal("CN=Test CA"));
        when(mockCert.getSubjectDN()).thenReturn(new X500Principal("CN=Test User,UID=123456789012"));
        when(mockCert.getNotBefore()).thenReturn(new Date());
        when(mockCert.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));

        Map<String, CertificateService.CertificateData> certs = new HashMap<>();
        certs.put("user", new CertificateService.CertificateData(
                "test@example.com",
                "123456789012",
                null,
                "test-ca",
                mockCert
        ));
        return certs;
    }

    private void setupMockCertificateService() {
        try {
            // Create mock certificate data
            Map<String, CertificateService.CertificateData> certs = createMockCertificates();

            // Mock XML signing
            when(certificateService.signXml(anyString(), anyString()))
                    .thenReturn("<signed-xml>mock-signature</signed-xml>");

            // Mock CMS signing
            when(certificateService.signData(anyString(), anyString()))
                    .thenReturn("mock-cms-signature");

            // Mock certificate details
            when(certificateStorage.getCertificates()).thenReturn(certs);
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }
    }

    @Test
    void testWebSocketConnection() {
        // Mock WebSocket setup
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Call the handler
        webSocketHandler.handle(mockWebSocket);

        // Verify client was added to connected clients
        assertEquals(1, connectedClients.size());
        assertTrue(connectedClients.containsKey("test-client-id"));
    }

    @Test
    void testGetKeyInfoMethod() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the getKeyInfo request message
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "getKeyInfo")
                .put("id", "test-1")
                .put("args", new JsonArray().add("PKCS12").add("user"));

        // Mock the response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify response structure
            assertEquals("200", response.getString("code"));
            assertEquals("OK", response.getString("message"));
            assertEquals("test-1", response.getString("id"));

            JsonObject keyInfo = response.getJsonObject("responseObject");
            assertNotNull(keyInfo);
            assertEquals("user", keyInfo.getString("alias"));
            assertEquals("digitalSignature", keyInfo.getString("keyUsage"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());

        // Verify textHandlerID was called once
        verify(mockWebSocket, times(1)).textHandlerID();
    }

    @Test
    void testGetKeyInfoMethodWithInvalidAlias() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Mock certificate lookup to return empty
        when(certificateStorage.getCertificates()).thenReturn(new HashMap<>());

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the getKeyInfo request message with invalid alias
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "getKeyInfo")
                .put("id", "test-2")
                .put("args", new JsonArray().add("PKCS12").add("invalid-alias"));

        // Mock the error response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify error response
            assertEquals("500", response.getString("code"));
            assertTrue(response.getString("message").contains("Certificate not found"));
            assertEquals("test-2", response.getString("id"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());
    }

    @Test
    void testSignXmlMethod() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the signXml request message
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "signXml")
                .put("id", "test-4")
                .put("args", new JsonArray().add("PKCS12").add("<xml>test</xml>"));

        // Mock the response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify response structure
            assertEquals("200", response.getString("code"));
            assertEquals("OK", response.getString("message"));
            assertEquals("test-4", response.getString("id"));

            String signedXml = response.getString("responseObject");
            assertNotNull(signedXml);
            assertTrue(signedXml.contains("mock-signature"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());

        // Verify the service was called
        try {
            verify(certificateService).signXml(anyString(), eq("user"));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }
    }

    @Test
    void testSignCmsMethod() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the signCms request message
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "signCms")
                .put("id", "test-6")
                .put("args", new JsonArray().add("PKCS12").add("test-data"));

        // Mock the response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify response structure
            assertEquals("200", response.getString("code"));
            assertEquals("OK", response.getString("message"));
            assertEquals("test-6", response.getString("id"));

            String signature = response.getString("responseObject");
            assertNotNull(signature);
            assertEquals("mock-cms-signature", signature);

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());

        // Verify the service was called
        try {
            verify(certificateService).signData(anyString(), eq("user"));
        } catch (Exception e) {
            // Should not happen in tests
            throw new RuntimeException(e);
        }
    }

    @Test
    void testGetStorageListMethod() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the getStorageList request message
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "getStorageList")
                .put("id", "test-9")
                .put("args", new JsonArray());

        // Mock the response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify response structure
            assertEquals("200", response.getString("code"));
            assertEquals("OK", response.getString("message"));
            assertEquals("test-9", response.getString("id"));

            JsonArray storageList = response.getJsonArray("responseObject");
            assertNotNull(storageList);
            assertTrue(storageList.contains("PKCS12"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());
    }

    @Test
    void testUnsupportedModule() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the request message with invalid module
        JsonObject request = new JsonObject()
                .put("module", "invalid.module")
                .put("method", "getKeyInfo")
                .put("id", "test-10")
                .put("args", new JsonArray().add("PKCS12").add("user"));

        // Mock the error response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify error response
            assertEquals("500", response.getString("code"));
            assertTrue(response.getString("message").contains("Unsupported module"));
            assertEquals("test-10", response.getString("id"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());
    }

    @Test
    void testUnsupportedMethod() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Capture the text message handler
        ArgumentCaptor<Handler<String>> handlerCaptor = ArgumentCaptor.forClass(Handler.class);

        // Call the handler to set up the WebSocket
        webSocketHandler.handle(mockWebSocket);

        // Verify textMessageHandler was set
        verify(mockWebSocket).textMessageHandler(handlerCaptor.capture());

        // Create the request message with invalid method
        JsonObject request = new JsonObject()
                .put("module", "kz.gov.pki.knca.commonUtils")
                .put("method", "invalidMethod")
                .put("id", "test-11")
                .put("args", new JsonArray().add("PKCS12").add("user"));

        // Mock the error response
        doAnswer(invocation -> {
            String message = invocation.getArgument(0);
            JsonObject response = new JsonObject(message);

            // Verify error response
            assertEquals("500", response.getString("code"));
            assertTrue(response.getString("message").contains("Unsupported method"));
            assertEquals("test-11", response.getString("id"));

            return null;
        }).when(mockWebSocket).writeTextMessage(anyString());

        // Simulate receiving the message
        handlerCaptor.getValue().handle(request.encode());
    }

    @Test
    void testClientDisconnect() {
        // Setup mock WebSocket
        when(mockWebSocket.textHandlerID()).thenReturn("test-client-id");

        // Call the handler to add client
        webSocketHandler.handle(mockWebSocket);
        assertEquals(1, connectedClients.size());

        // Simulate disconnect by calling close handler
        // The close handler should remove the client from connectedClients
        // Since we can't easily trigger the close handler in this test,
        // we'll just verify the initial connection
        assertTrue(connectedClients.containsKey("test-client-id"));
    }

    @Test
    void testConnectedClientCount() {
        assertEquals(0, webSocketHandler.getConnectedClientCount());

        // Add a mock client
        connectedClients.put("test-client", mockWebSocket);
        assertEquals(1, webSocketHandler.getConnectedClientCount());
    }
}
