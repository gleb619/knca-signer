package knca.signer.controller;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;

/**
 * Handler for certificate-related operations including certificate retrieval and generation.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificatorHandler {

    private final CertificateService certificateService;
    private final CertificateStorage storageService;

    /**
     * Handles requests to retrieve CA certificate information.
     *
     * @return Handler for getting CA certificates
     */
    public Handler<RoutingContext> handleGetCACertificate() {
        return ctx -> handleGetCertificates(ctx, "CA", storageService.getCACertificates(), (alias, data) -> buildCertificateDto(alias, data, false));
    }

    /**
     * Handles requests to retrieve user certificate information for a specific CA.
     *
     * @return Handler for getting user certificates for a CA
     */
    public Handler<RoutingContext> handleGetUserCertificate() {
        return ctx -> handleGetCertificatesForCA(ctx, "user", storageService.getUserCertificates(), (alias, data) -> buildCertificateDto(alias, data, true));
    }

    /**
     * Handles requests to generate CA certificate.
     *
     * @return Handler for generating CA certificate
     */
    public Handler<RoutingContext> handleGenerateCACertificate() {
        return ctx -> {
            try {
                var alias = ctx.queryParam("alias").stream().findFirst().orElse(null);
                log.info("Generating new CA certificate with alias: {}", alias);
                var entry = certificateService.generateCACertificate(alias);
                var certData = storageService.getCACertificates().get(entry.getKey());
                var dto = buildCertificateDto(entry.getKey(), certData, false).toBuilder()
                        .type("ca")
                        .generated(true)
                        .build();
                log.info("CA certificate generated successfully with alias: {}", entry.getKey());
                sendJsonResponse(ctx, dto);
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

    /**
     * Handles requests to retrieve legal entity certificate information for a specific CA.
     *
     * @return Handler for getting legal certificates for a CA
     */
    public Handler<RoutingContext> handleGetLegalCertificate() {
        return ctx -> handleGetCertificatesForCA(ctx, "legal", storageService.getLegalCertificates(), (alias, data) -> buildCertificateDto(alias, data, true));
    }

    /**
     * Handles requests to retrieve all certificates from the filesystem with full CertificateInfo.
     *
     * @return Handler for reading filesystem certificates
     */
    public Handler<RoutingContext> handleGetFilesystemCertificates() {
        return ctx -> {
            try {
                log.info("Retrieving all certificates from memory cache");
                var certificates = certificateService.getFilesystemCertificates();
                var result = new JsonObject();
                var filesArray = new io.vertx.core.json.JsonArray();
                for (var certInfo : certificates) {
                    var dto = CertificateDto.builder()
                            .type(certInfo.getType())
                            .filename(certInfo.getFilename())
                            .serialNumber(certInfo.getSerialNumber())
                            .issuer(certInfo.getIssuer())
                            .subject(certInfo.getSubject())
                            .notBefore(certInfo.getNotBefore())
                            .notAfter(certInfo.getNotAfter())
                            .email(certInfo.getEmail())
                            .iin(certInfo.getIin())
                            .bin(certInfo.getBin())
                            .publicKeyAlgorithm(certInfo.getPublicKeyAlgorithm())
                            .keySize(certInfo.getKeySize())
                            .build();
                    filesArray.add(dto);
                }
                result.put("certificates", filesArray);
                sendJsonResponse(ctx, result);
            } catch (Exception e) {
                handleError(ctx, "retrieving filesystem certificates", e);
            }
        };
    }

    /**
     * Handles requests to download certificate files in different formats.
     *
     * @return Handler for downloading certificate files
     */
    public Handler<RoutingContext> handleDownloadCertificate() {
        return ctx -> {
            try {
                var alias = ctx.pathParam("alias");
                var format = ctx.pathParam("format");

                log.info("Downloading certificate with alias: {} in format: {}", alias, format);

                var certificateData = certificateService.downloadCertificate(alias, format);
                if (certificateData == null) {
                    ctx.response().setStatusCode(404).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "Certificate not found").encode());
                    return;
                }

                var filename = certificateData.getFilename();
                var contentType = getContentTypeForFormat(format);
                var contentDisposition = "attachment; filename=\"" + filename + "\"";

                ctx.response()
                        .putHeader("Content-Type", contentType)
                        .putHeader("Content-Disposition", contentDisposition)
                        .putHeader("Cache-Control", "no-cache")
                        .end(Buffer.buffer(certificateData.getData()));

                log.info("Successfully sent certificate file: {}", filename);
            } catch (Exception e) {
                handleError(ctx, "downloading certificate", e);
            }
        };
    }

    private String getContentTypeForFormat(String format) {
        return switch (format.toLowerCase()) {
            case "crt", "pem" -> "application/x-pem-file";
            case "p12" -> "application/x-pkcs12";
            case "jks" -> "application/octet-stream";
            default -> "application/octet-stream";
        };
    }

    /* ============= */

    private <T> void handleGetCertificates(RoutingContext ctx, String type, Map<String, T> certs, CertDtoBuilder<T> builder) {
        try {
            log.info("Retrieving {} certificates", type);
            var result = new JsonObject();
            var certList = new io.vertx.core.json.JsonArray();
            certs.forEach((alias, data) -> certList.add(builder.build(alias, data)));
            result.put("certificates", certList);
            sendJsonResponse(ctx, result);
        } catch (Exception e) {
            handleError(ctx, "retrieving " + type + " certificates", e);
        }
    }

    private <T> void handleGetCertificatesForCA(RoutingContext ctx, String type, Map<String, T> certs, CertDtoBuilder<T> builder) {
        try {
            var caId = extractCaIdFromQuery(ctx);
            log.info("Retrieving {} certificates for CA: {}", type, caId);
            var result = new JsonObject();
            var certList = new io.vertx.core.json.JsonArray();
            certs.entrySet().stream()
                    .filter(entry -> {
                        if (type.equals("user") || type.equals("legal")) {
                            var data = (CertificateService.CertificateData) entry.getValue();
                            return caId.equals(data.getCaId());
                        }
                        return true; // For CA certificates, return all
                    })
                    .forEach(entry -> certList.add(builder.build(entry.getKey(), entry.getValue())));
            result.put("certificates", certList);
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
            var dto = buildCertificateDto(entry.getKey(), entry.getValue(), true).toBuilder()
                    .type(type)
                    .caId(caId)
                    .generated(true)
                    .build();
            log.info("{} certificate generated successfully with alias: {}", logType, entry.getKey());
            sendJsonResponse(ctx, dto);
        } catch (Exception e) {
            handleError(ctx, "generating " + type + " certificate", e);
        }
    }

    private CertificateDto buildCertificateDto(String alias, Object certData, boolean includeCaId) {
        var data = (CertificateService.CertificateData) certData;
        var cert = data.getCertificate();

        // Get the basic certificate serial number, issuer, subject from certificate itself
        String serialNumber = cert.getSerialNumber().toString();
        String issuer = cert.getIssuerDN().getName();
        String subject = cert.getSubjectDN().getName();
        LocalDateTime notBefore = toLocalDateTime(cert.getNotBefore().toInstant());
        LocalDateTime notAfter = toLocalDateTime(cert.getNotAfter().toInstant());

        // Get algorithm info from certificate
        String publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
        Integer keySize = null;
        try {
            if ("RSA".equals(publicKeyAlgorithm)) {
                keySize = ((java.security.interfaces.RSAPublicKey) cert.getPublicKey()).getModulus().bitLength();
            }
        } catch (Exception e) {
            log.debug("Could not determine key size: {}", e.getMessage());
        }

        // Use pre-extracted data from CertificateData for email, iin, bin
        // Determine type based on certificate subject
        String type;
        String filename;
        if (subject.contains("OU=BIN")) {
            type = "LEGAL";
            filename = alias + ".p12";
        } else {
            type = "USER";
            filename = alias + ".p12";
        }
        if (cert.getSubjectDN().getName().contains("KUÄ") || cert.getSubjectDN().getName().contains("КУӘ")) {
            type = "CA";
            filename = alias + ".crt";
        }

        var builder = CertificateDto.builder()
                .alias(alias)
                .type(type)
                .filename(filename)
                .serialNumber(serialNumber)
                .issuer(issuer)
                .subject(subject)
                .notBefore(notBefore)
                .notAfter(notAfter)
                .email(data.getEmail())
                .iin(data.getIin())
                .bin(data.getBin())
                .publicKeyAlgorithm(publicKeyAlgorithm)
                .keySize(keySize);

        if (includeCaId) {
            builder.caId(data.getCaId());
        }

        return builder.build();
    }



    private LocalDateTime toLocalDateTime(java.time.Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    private String extractCaId(RoutingContext ctx) {
        var body = ctx.body().asJsonObject();
        return body != null && body.containsKey("caId") ? body.getString("caId", "ca") : "ca";
    }

    private String extractCaIdFromQuery(RoutingContext ctx) {
        return ctx.queryParam("caId").stream().findFirst().orElse("ca");
    }

    private void sendJsonResponse(RoutingContext ctx, JsonObject json) {
        ctx.response().putHeader("content-type", "application/json").end(json.encode());
    }

    private void sendJsonResponse(RoutingContext ctx, CertificateDto dto) {
        ctx.response().putHeader("content-type", "application/json").end(io.vertx.core.json.Json.encode(dto));
    }

    private void handleError(RoutingContext ctx, String action, Exception e) {
        log.error("Error {}: {}", action, e.getMessage(), e);
        ctx.response().setStatusCode(500).putHeader("content-type", "application/json")
                .end(new JsonObject().put("error", "Internal server error").encode());
    }

    @FunctionalInterface
    private interface CertDtoBuilder<T> {

        CertificateDto build(String alias, T data);

    }

    @FunctionalInterface
    private interface CertGenerator {

        Map.Entry<String, ?> generate(String caId);

    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class CertificateDto {

        private String alias;
        private String type;
        private String filename;
        private String serialNumber;
        private String issuer;
        private String subject;
        private LocalDateTime notBefore;
        private LocalDateTime notAfter;
        private String email;
        private String iin;
        private String bin;
        private String publicKeyAlgorithm;
        private Integer keySize;
        private String caId;
        private Boolean generated;

    }


}
