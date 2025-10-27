package knca.signer.controller;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.json.JsonObject;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class WebSocketHandler implements Handler<ServerWebSocket> {

    private final CertificateService certificateService;
    private final CertificateStorage storage;
    private final Map<String, ServerWebSocket> connectedClients;
    private final Vertx vertx;
    private final EventBus eventBus;

    public WebSocketHandler init() {
        // Register event bus consumer for broadcasting messages
        eventBus.consumer("signature.events", message -> {
            JsonObject event = (JsonObject) message.body();
            broadcastEvent(event);
        });

        return this;
    }

    @Override
    public void handle(ServerWebSocket webSocket) {
        String clientId = webSocket.textHandlerID();
        connectedClients.put(clientId, webSocket);

        log.info("WebSocket client connected: " + clientId);

        // Handle incoming messages
        webSocket.textMessageHandler(message -> {
            try {
                JsonObject request = new JsonObject(message);
                String module = request.getString("module");
                String method = request.getString("method");
                String id = request.getString("id");

                if (module == null || method == null || id == null) {
                    sendNcaError(webSocket, "Missing required fields: module, method, id", id);
                    return;
                }

                if ("kz.gov.pki.knca.commonUtils".equals(module)) {
                    handleCommonUtilsMethod(webSocket, method, request.getJsonArray("args"), id);
                } else {
                    sendNcaError(webSocket, "Unsupported module: " + module, id);
                }
            } catch (Exception e) {
                sendNcaError(webSocket, "Invalid message format: " + e.getMessage(), null);
            }
        });

        // Handle client disconnect
        webSocket.closeHandler(v -> {
            connectedClients.remove(clientId);
            log.info("WebSocket client disconnected: " + clientId);
        });

        // Handle errors
        webSocket.exceptionHandler(e -> {
            log.error("WebSocket error for client " + clientId + ": " + e.getMessage());
            connectedClients.remove(clientId);
        });
    }

    private void handleCommonUtilsMethod(ServerWebSocket webSocket, String method, io.vertx.core.json.JsonArray args, String id) {
        try {
            switch (method) {
                case "getKeyInfo":
                    handleGetKeyInfo(webSocket, args, id);
                    break;
                case "signXml":
                    handleSignXml(webSocket, args, id);
                    break;
                case "signCms":
                    handleSignCms(webSocket, args, id);
                    break;
                case "getStorageList":
                    handleGetStorageList(webSocket, id);
                    break;
                default:
                    sendNcaError(webSocket, "Unsupported method: " + method, id);
                    break;
            }
        } catch (Exception e) {
            sendNcaError(webSocket, "Failed to process " + method + ": " + e.getMessage(), id);
        }
    }

    private void handleGetKeyInfo(ServerWebSocket webSocket, io.vertx.core.json.JsonArray args, String id) {
        if (args == null || args.size() < 2) {
            sendNcaError(webSocket, "getKeyInfo requires storage type and alias", id);
            return;
        }

        String storageType = args.getString(0);
        String alias = args.getString(1);

        try {
            Map<String, CertificateService.CertificateData> certs = storage.getCertificates();
            CertificateService.CertificateData certData = certs.get(alias);

            if (certData == null) {
                sendNcaError(webSocket, "Certificate not found: " + alias, id);
                return;
            }

            JsonObject keyInfo = new JsonObject()
                    .put("subjectDn", certData.getCertificate().getSubjectDN().getName())
                    .put("issuerDn", certData.getCertificate().getIssuerDN().getName())
                    .put("serialNumber", certData.getCertificate().getSerialNumber().toString())
                    .put("alias", alias)
                    .put("keyUsage", "digitalSignature")
                    .put("notBefore", certData.getCertificate().getNotBefore().getTime())
                    .put("notAfter", certData.getCertificate().getNotAfter().getTime());

            JsonObject response = new JsonObject()
                    .put("responseObject", keyInfo)
                    .put("code", "200")
                    .put("message", "OK")
                    .put("id", id);

            webSocket.writeTextMessage(response.encode());

        } catch (Exception e) {
            sendNcaError(webSocket, "Failed to get key info: " + e.getMessage(), id);
        }
    }

    private void handleSignXml(ServerWebSocket webSocket, io.vertx.core.json.JsonArray args, String id) {
        if (args == null || args.size() < 2) {
            sendNcaError(webSocket, "signXml requires storage type and XML data", id);
            return;
        }

        String storageType = args.getString(0);
        String xmlData = args.getString(1);

        vertx.executeBlocking(promise -> {
            try {
                // Use the real XML signing implementation
                String signedXml = certificateService.signXml(xmlData, "user");

                JsonObject response = new JsonObject()
                        .put("responseObject", signedXml)
                        .put("code", "200")
                        .put("message", "OK")
                        .put("id", id);

                webSocket.writeTextMessage(response.encode());
                promise.complete();

            } catch (Exception e) {
                sendNcaError(webSocket, "Failed to sign XML: " + e.getMessage(), id);
                promise.fail(e);
            }
        }, false, null);
    }

    private void handleSignCms(ServerWebSocket webSocket, io.vertx.core.json.JsonArray args, String id) {
        if (args == null || args.size() < 2) {
            sendNcaError(webSocket, "signCms requires storage type and data", id);
            return;
        }

        String storageType = args.getString(0);
        String data = args.getString(1);
        boolean detached = args.size() > 2 ? args.getBoolean(2) : true;

        vertx.executeBlocking(promise -> {
            try {
                // Decode base64 data if needed
                byte[] dataBytes;
                try {
                    dataBytes = java.util.Base64.getDecoder().decode(data);
                } catch (IllegalArgumentException e) {
                    // If not base64, treat as UTF-8 string
                    dataBytes = data.getBytes(StandardCharsets.UTF_8);
                }

                String signature = certificateService.signData(new String(dataBytes, StandardCharsets.UTF_8), "user");

                JsonObject response = new JsonObject()
                        .put("responseObject", signature)
                        .put("code", "200")
                        .put("message", "OK")
                        .put("id", id);

                webSocket.writeTextMessage(response.encode());
                promise.complete();

            } catch (Exception e) {
                sendNcaError(webSocket, "Failed to sign CMS: " + e.getMessage(), id);
                promise.fail(e);
            }
        }, false, null);
    }

    private void handleGetStorageList(ServerWebSocket webSocket, String id) {
        try {
            Map<String, CertificateService.CertificateData> certs = storage.getCertificates();
            io.vertx.core.json.JsonArray storageList = new io.vertx.core.json.JsonArray();
            storageList.add("PKCS12");

            JsonObject response = new JsonObject()
                    .put("responseObject", storageList)
                    .put("code", "200")
                    .put("message", "OK")
                    .put("id", id);

            webSocket.writeTextMessage(response.encode());

        } catch (Exception e) {
            sendNcaError(webSocket, "Failed to get storage list: " + e.getMessage(), id);
        }
    }

    private void sendNcaError(ServerWebSocket webSocket, String message, String id) {
        JsonObject error = new JsonObject()
                .put("responseObject", null)
                .put("code", "500")
                .put("message", message);

        if (id != null) {
            error.put("id", id);
        }

        webSocket.writeTextMessage(error.encode());
    }

    private void broadcastEvent(JsonObject event) {
        String message = event.encode();
        connectedClients.values().forEach(ws -> {
            if (!ws.isClosed()) {
                ws.writeTextMessage(message);
            }
        });
    }

    public void broadcastSignatureEvent(String eventType, String details) {
        JsonObject event = new JsonObject()
                .put("type", "signature_event")
                .put("eventType", eventType)
                .put("details", details)
                .put("timestamp", System.currentTimeMillis());

        eventBus.publish("signature.events", event);
    }

    public int getConnectedClientCount() {
        return connectedClients.size();
    }
}
