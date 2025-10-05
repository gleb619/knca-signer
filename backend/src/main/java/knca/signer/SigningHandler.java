package knca.signer;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import knca.signer.service.CertificateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class SigningHandler {

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

                String signature = certificateService.signData(data, certAlias);
                log.info("Data signed successfully with certAlias: {}", certAlias);

                respondJson(ctx, new JsonObject()
                        .put("signature", signature)
                        .put("certAlias", certAlias)
                        .put("algorithm", "SHA256withRSA"));

            } catch (IllegalArgumentException e) {
                log.warn("Invalid certificate alias in sign request: {}", e.getMessage());
                respondError(ctx, 404, e.getMessage());
            } catch (Exception e) {
                log.error("Error signing data: {}", e.getMessage(), e);
                respondError(ctx, 500, "Internal server error");
            }
        };
    }

    /**
     * Handles signature verification requests.
     * Expects JSON with "data", "signature", and optional "certAlias" (defaults to "user").
     *
     * @return Handler for verifying signatures
     */
    public Handler<RoutingContext> handleVerifySignature() {
        return ctx -> {
            try {
                JsonObject req = ctx.getBodyAsJson();
                String data = req.getString("data");
                String signature = req.getString("signature");
                String certAlias = req.getString("certAlias", DEFAULT_CERT_ALIAS);

                log.info("Verifying signature with certAlias: {}", certAlias);

                if (data == null || signature == null) {
                    log.warn("Data and signature are required for verification");
                    respondError(ctx, 400, "Data and signature are required");
                    return;
                }

                boolean isValid = certificateService.verifySignature(data, signature, certAlias);
                log.info("Signature verification result for certAlias {}: {}", certAlias, isValid);

                respondJson(ctx, new JsonObject()
                        .put("valid", isValid)
                        .put("certAlias", certAlias));

            } catch (IllegalArgumentException e) {
                log.warn("Invalid certificate alias in verify request: {}", e.getMessage());
                respondError(ctx, 404, e.getMessage());
            } catch (Exception e) {
                log.error("Error verifying signature: {}", e.getMessage(), e);
                respondError(ctx, 500, "Internal server error");
            }
        };
    }

    /**
     * Handles XML signature validation requests.
     * Expects JSON with "xml" content.
     *
     * @return Handler for validating XML signatures
     */
    public Handler<RoutingContext> handleValidateXml() {
        return ctx -> {
            try {
                JsonObject req = ctx.getBodyAsJson();
                String xmlContent = req.getString("xml");

                log.info("Validating XML signature");

                if (xmlContent == null || xmlContent.isEmpty()) {
                    log.warn("XML content is required for validation");
                    respondError(ctx, 400, "XML content is required");
                    return;
                }

                boolean isValid = certificateService.validateXmlSignature(xmlContent);
                log.info("XML validation result: {}", isValid);

                respondJson(ctx, new JsonObject()
                        .put("valid", isValid)
                        .put("message", isValid ? "XML signature is valid" : "XML signature is invalid"));

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
}