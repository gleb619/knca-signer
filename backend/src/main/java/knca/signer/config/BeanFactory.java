package knca.signer.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.vertx.core.Vertx;
import io.vertx.core.json.jackson.DatabindCodec;
import knca.signer.CertificateHandler;
import knca.signer.SigningHandler;
import knca.signer.WebSocketHandler;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateReader;
import knca.signer.service.CertificateService;
import lombok.RequiredArgsConstructor;

/**
 * Simple IoC container for managing application beans
 */
@RequiredArgsConstructor
public class BeanFactory {

    private final Vertx vertx;
    private final ApplicationConfig config;

    // Singleton instances
    private CertificateService certificateService;
    private WebSocketHandler webSocketHandler;
    private CertificateHandler certificateHandler;
    private SigningHandler signingHandler;


    public BeanFactory init() {
        DatabindCodec.mapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        getCertificateService().init();

        return this;
    }

    public CertificateService getCertificateService() {
        if (certificateService == null) {
            try {
                certificateService = new CertificateService(KalkanRegistry.loadRealKalkanProvider(), config.getCertificate());
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize CertificateService", e);
            }
        }
        return certificateService;
    }

    public WebSocketHandler getWebSocketHandler() {
        if (webSocketHandler == null) {
            webSocketHandler = new WebSocketHandler(getCertificateService(), vertx);
        }
        return webSocketHandler;
    }

    public CertificateHandler getCertificateHandler() {
        if (certificateHandler == null) {
            certificateHandler = new CertificateHandler(getCertificateService(), new CertificateReader(config.getCertificate()));
        }
        return certificateHandler;
    }

    public SigningHandler getSigningHandler() {
        if (signingHandler == null) {
            signingHandler = new SigningHandler(getCertificateService());
        }
        return signingHandler;
    }
}
