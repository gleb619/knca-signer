package knca.signer.controller;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateService.ValidationResult;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class VerifierHandler {

    private static final String CONTENT_TYPE = "application/json";
    private static final String DEFAULT_CERT_ALIAS = "user";

    private final CertificateService certificateService;


    /**
     * Handles data signing requests.
     * Expects JSON with "data" and optional "certAlias" (defaults to "user").
     *
     * @return Handler for signing data
     */
    public Handler<RoutingContext> handleSignData() {
        return ctx -> {
            try {
                JsonObject req = ctx.getBodyAsJson();
                String data = req.getString("data");
                String certAlias = req.getString("certAlias", DEFAULT_CERT_ALIAS);

                log.info("Signing data with certAlias: {}", certAlias);

                if (data == null || data.isEmpty()) {
                    log.warn("Data is required for signing");
                    respondError(ctx, 400, "Data is required");
                    return;
                }

                String signedXml = certificateService.signXml(data, certAlias);
                log.info("Data signed successfully with certAlias: {}", certAlias);

                respondJson(ctx, JsonObject.mapFrom(
                        new SignResult(signedXml, certAlias, "XMLDSig")));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid certificate alias in XML sign request: {}", e.getMessage());
                respondError(ctx, 404, e.getMessage());
            } catch (Exception e) {
                log.error("Error signing XML: {}", e.getMessage(), e);
                respondError(ctx, 500, "Internal server error");
            }
        };
    }

    /**
     * Handles XML signature validation requests.
     * Expects JSON with "xml" and validation configuration.
     *
     * @return Handler for validating XML signatures
     */
    public Handler<RoutingContext> handleValidateXml() {
        return ctx -> {
            try {
                XmlValidationRequest validationRequest = ctx.body().asPojo(XmlValidationRequest.class);

                log.info("Validating XML signature with configuration");

                if (validationRequest.getXml() == null || validationRequest.getXml().isEmpty()) {
                    log.warn("XML content is required for validation");
                    respondError(ctx, 400, "XML content is required");
                    return;
                }

                ValidationResult result = certificateService.validateXmlSignature(validationRequest);
                log.info("XML validation result: {}", result.isValid());

                respondJson(ctx, JsonObject.mapFrom(result));

            } catch (Exception e) {
                log.error("Error validating XML signature: {}", e.getMessage(), e);
                respondError(ctx, 500, "XML validation failed: " + e.getMessage());
            }
        };
    }

    private void respondJson(RoutingContext ctx, JsonObject json) {
        ctx.response()
                .putHeader("content-type", CONTENT_TYPE)
                .end(json.encode());
    }

    private void respondError(RoutingContext ctx, int code, String msg) {
        ctx.response()
                .setStatusCode(code)
                .putHeader("content-type", CONTENT_TYPE)
                .end(new JsonObject().put("error", msg).encode());
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class XmlValidationRequest {

        private String xml;
        private String publicKey; // Optional base64 encoded public key
        private String caPem; // Optional base64 encoded CA certificate PEM
        @Builder.Default
        private boolean checkSignature = true; // Enable signature validation by default
        @Builder.Default
        private boolean checkKncaProvider = false;
        @Builder.Default
        private boolean checkIinInCert = false;
        @Builder.Default
        private boolean checkBinInCert = false;
        @Builder.Default
        private boolean checkCertificateChain = false;
        @Builder.Default
        private boolean checkPublicKey = false;
        @Builder.Default
        private boolean checkExtendedKeyUsage = false;
        private String extendedKeyUsageOids; // Comma-separated list of OIDs to check in certificate's ExtendedKeyUsage
        private String expectedIin; // Optional expected IIN
        private String expectedBin; // Optional expected BIN for legal certificates

    }

    public record SignResult(String xml, String certAlias, String algorithm) {
    }

}
