package knca.signer.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.vertx.core.Vertx;
import io.vertx.core.json.jackson.DatabindCodec;
import knca.signer.config.ApplicationConfig.CertificateConfig;
import knca.signer.controller.CertificatorHandler;
import knca.signer.controller.VerifierHandler;
import knca.signer.controller.WebSocketHandler;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorageService;
import knca.signer.service.CertificateValidator;
import lombok.RequiredArgsConstructor;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple IoC container for managing application beans
 */
@RequiredArgsConstructor
public class BeanFactory {

    private final Vertx vertx;
    private final ApplicationConfig config;

    // Singleton instances
    private CertificateStorageService certificateStorageService;
    private CertificateService certificateService;
    private WebSocketHandler webSocketHandler;
    private CertificatorHandler certificateHandler;
    private VerifierHandler signingHandler;


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

    public CertificateStorageService getCertificateStorageService() {
        if (certificateStorageService == null) {
            certificateStorageService = createStorage();
        }

        return certificateStorageService;
    }

    public CertificateService getCertificateService() {
        if (certificateService == null) {
            try {
                var provider = KalkanRegistry.loadRealKalkanProvider();
                var certConfig = config.getCertificate();

                var storage = getCertificateStorageService();
                // Create individual services
                var generationService = createGenerationService(provider, storage, certConfig);
                var validationService = createValidationService(provider, storage);

                // Create facade and inject services
                certificateService = new CertificateService(provider, certConfig, storage, generationService, validationService);

            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize CertificateService", e);
            }
        }
        return certificateService;
    }

    private CertificateStorageService createStorage() {
        return new CertificateStorageService(new CertificateStorageService.CertificateStorage());
    }

    private CertificateGenerator createGenerationService(java.security.Provider provider,
                                                         CertificateStorageService registry,
                                                         CertificateConfig config) {
        return new CertificateGenerator(provider, config, registry);
    }

    private CertificateValidator createValidationService(java.security.Provider provider, CertificateStorageService registry) {
        return new CertificateValidator(provider, registry);
    }

    public WebSocketHandler getWebSocketHandler() {
        if (webSocketHandler == null) {
            var service = getCertificateService();
            var storage = getCertificateStorageService();

            webSocketHandler = new WebSocketHandler(service, storage, new ConcurrentHashMap<>(), vertx, vertx.eventBus());
        }
        return webSocketHandler;
    }

    public CertificatorHandler getCertificateHandler() {
        if (certificateHandler == null) {
            certificateHandler = new CertificatorHandler(getCertificateService(), getCertificateStorageService());
        }
        return certificateHandler;
    }

    public VerifierHandler getSigningHandler() {
        if (signingHandler == null) {
            signingHandler = new VerifierHandler(getCertificateService());
        }
        return signingHandler;
    }
}
