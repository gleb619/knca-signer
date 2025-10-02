package knca.signer;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import knca.signer.service.CertificateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;

/**
 * Handler for certificate-related operations including certificate retrieval and generation.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateHandler {

    private final CertificateService certificateService;

    /**
     * Handles requests to retrieve CA certificate information.
     *
     * @return Handler for getting CA certificates
     */
    public Handler<RoutingContext> handleGetCACertificate() {
        return ctx -> handleGetCertificates(ctx, "CA", certificateService.getCACertificates(), this::buildCACertJson);
    }

    /**
     * Handles requests to retrieve user certificate information.
     *
     * @return Handler for getting user certificates
     */
    public Handler<RoutingContext> handleGetUserCertificate() {
        return ctx -> handleGetCertificates(ctx, "user", certificateService.getUserCertificates(), this::buildEntityCertJson);
    }

    /**
     * Handles requests to retrieve legal entity certificate information.
     *
     * @return Handler for getting legal certificates
     */
    public Handler<RoutingContext> handleGetLegalCertificate() {
        return ctx -> handleGetCertificates(ctx, "legal", certificateService.getLegalCertificates(), this::buildEntityCertJson);
    }

    /**
     * Handles requests to generate CA certificate.
     *
     * @return Handler for generating CA certificate
     */
    public Handler<RoutingContext> handleGenerateCACertificate() {
        return ctx -> {
            try {
                log.info("Generating new CA certificate");
                var alias = certificateService.generateCACertificate(null).getKey();
                var certData = certificateService.getCACertificates().get(alias);
                var response = buildCACertJson(alias, certData).put("type", "ca").put("generated", true);
                log.info("CA certificate generated successfully with alias: {}", alias);
                sendJsonResponse(ctx, response);
            } catch (Exception e) {
                handleError(ctx, "generating CA certificate", e);
            }
        };
    }

    /**
     * Handles requests to generate user certificate.
     *
     * @return Handler for generating user certificate
     */
    public Handler<RoutingContext> handleGenerateUserCertificate() {
        return ctx -> handleGenerateEntityCert(ctx, "user", "User", certificateService::generateUserCertificate);
    }

    public Handler<RoutingContext> handleGenerateLegalCertificate() {
        return ctx -> handleGenerateEntityCert(ctx, "legal", "Legal", certificateService::generateLegalEntityCertificate);
    }

    /* ============= */

    private <T> void handleGetCertificates(RoutingContext ctx, String type, Map<String, T> certs, CertJsonBuilder<T> builder) {
        try {
            log.info("Retrieving {} certificates", type);
            var result = new JsonObject();
            certs.forEach((alias, data) -> result.put(alias, builder.build(alias, data)));
            sendJsonResponse(ctx, result);
        } catch (Exception e) {
            handleError(ctx, "retrieving " + type + " certificates", e);
        }
    }

    private void handleGenerateEntityCert(RoutingContext ctx, String type, String logType, CertGenerator generator) {
        try {
            var caId = extractCaId(ctx);
            log.info("Generating new {} certificate under CA: {}", type, caId);
            var entry = generator.generate(caId);
            var response = buildEntityCertJson(entry.getKey(), entry.getValue())
                    .put("type", type).put("caId", caId).put("generated", true);
            log.info("{} certificate generated successfully with alias: {}", logType, entry.getKey());
            sendJsonResponse(ctx, response);
        } catch (Exception e) {
            handleError(ctx, "generating " + type + " certificate", e);
        }
    }

    private JsonObject buildCACertJson(String alias, Object certData) {
        var cert = ((CertificateService.CertificateData) certData).getCertificate();
        return new JsonObject()
                .put("alias", alias)
                .put("subject", cert.getSubjectDN().getName())
                .put("issuer", cert.getIssuerDN().getName())
                .put("notBefore", toLocalDateTime(cert.getNotBefore().toInstant()))
                .put("notAfter", toLocalDateTime(cert.getNotAfter().toInstant()));
    }

    private JsonObject buildEntityCertJson(String alias, Object certData) {
        var data = (CertificateService.CertificateData) certData;
        return buildCACertJson(alias, certData)
                .put("caId", data.getCaId())
                .put("email", data.getEmail())
                .put("iin", data.getIin())
                .put("bin", data.getBin());
    }

    private LocalDateTime toLocalDateTime(java.time.Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    private String extractCaId(RoutingContext ctx) {
        var body = ctx.getBodyAsJson();
        return body != null && body.containsKey("caId") ? body.getString("caId", "default") : "default";
    }

    private void sendJsonResponse(RoutingContext ctx, JsonObject json) {
        ctx.response().putHeader("content-type", "application/json").end(json.encode());
    }

    private void handleError(RoutingContext ctx, String action, Exception e) {
        log.error("Error {}: {}", action, e.getMessage(), e);
        ctx.response().setStatusCode(500).putHeader("content-type", "application/json")
                .end(new JsonObject().put("error", "Internal server error").encode());
    }

    @FunctionalInterface
    private interface CertJsonBuilder<T> {
        JsonObject build(String alias, T data);
    }

    @FunctionalInterface
    private interface CertGenerator {
        Map.Entry<String, ?> generate(String caId);
    }
}