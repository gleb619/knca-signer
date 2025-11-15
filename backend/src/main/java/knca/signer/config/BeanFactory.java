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
import knca.signer.kalkan.KalkanException;
import knca.signer.kalkan.KalkanRegistry;
import knca.signer.service.CertificateGenerator;
import knca.signer.service.CertificateService;
import knca.signer.service.CertificateStorage;
import knca.signer.service.CertificateValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.Provider;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple IoC container for managing application beans
 */
@Slf4j
@RequiredArgsConstructor
public class BeanFactory {

    private final Vertx vertx;
    private final ApplicationConfig config;

    // Singleton instances
    private CertificateStorage certificateStorage;
    private CertificateService certificateService;
    private WebSocketHandler webSocketHandler;
    private CertificatorHandler certificateHandler;
    private VerifierHandler signingHandler;


    public BeanFactory init(boolean verboseMode) {
        DatabindCodec.mapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        try {
            getCertificateService().init();
        } catch (Exception e) {
            if (e instanceof KalkanException ke) {
                log.error("Found problem with kalkan: ", ke);
            } else if (verboseMode) {
                throw new RuntimeException(e);
            }
        }

        return this;
    }

    public CertificateStorage getCertificateStorage() {
        if (certificateStorage == null) {
            certificateStorage = createStorage();
        }

        return certificateStorage;
    }

    public CertificateService getCertificateService() {
        if (certificateService == null) {
            var provider = acquireProvider();
            try {
                var certConfig = config.getCertificate();

                var storage = getCertificateStorage();
                // Create individual services
                var generationService = createGenerationService(provider, storage, certConfig);
                var validationService = createValidationService(provider, storage);

                // Create facade and inject services
                certificateService = new CertificateService(provider, certConfig, storage, generationService, validationService);
            } catch (Exception e) {
                throw new RuntimeException("Failed to init CertificateService", e);
            }
        }
        return certificateService;
    }

    private CertificateStorage createStorage() {
        return new CertificateStorage(new CertificateStorage.Storage());
    }

    private CertificateGenerator createGenerationService(Provider provider,
                                                         CertificateStorage registry,
                                                         CertificateConfig config) {
        return new CertificateGenerator(provider, config, registry);
    }

    private CertificateValidator createValidationService(Provider provider, CertificateStorage registry) {
        return new CertificateValidator(provider, registry);
    }

    public WebSocketHandler getWebSocketHandler() {
        if (webSocketHandler == null) {
            var service = getCertificateService();
            var storage = getCertificateStorage();

            webSocketHandler = new WebSocketHandler(service, storage, new ConcurrentHashMap<>(), vertx, vertx.eventBus());
        }
        return webSocketHandler;
    }

    public CertificatorHandler getCertificateHandler() {
        if (certificateHandler == null) {
            certificateHandler = new CertificatorHandler(getCertificateService(), getCertificateStorage());
        }
        return certificateHandler;
    }

    public VerifierHandler getSigningHandler() {
        if (signingHandler == null) {
            signingHandler = new VerifierHandler(getCertificateService());
        }
        return signingHandler;
    }

    private Provider acquireProvider() {
        try {
            return KalkanRegistry.loadRealKalkanProvider();
        } catch (Exception e) {
            if (e instanceof KalkanException ke && ke.isSystemError()) {
                return new MockProvider();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Mock provider implementation used as a fallback when the real Kalkan provider
     * is not available in the classpath. This provider is used to maintain application
     * functionality during development or testing when the actual Kalkan library
     * dependencies are not present.
     */
    private static class MockProvider extends Provider {

        public MockProvider() {
            super("KALKAN", "0.0", "Mock Provider");
        }

        @Override
        public String getName() {
            return super.getName();
        }

    }

}
