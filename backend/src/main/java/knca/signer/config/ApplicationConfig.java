package knca.signer.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Application configuration holder
 */
@Data
public class ApplicationConfig {

    private HttpConfig http;
    private CorsConfig cors;
    private WebSocketConfig websocket;
    private StaticConfig staticConfig;
    private LoggingConfig logging;
    private CertificateConfig certificate;

    @Data
    public static class HttpConfig {

        private int port;
        private String host;

    }

    @Data
    public static class CorsConfig {

        private String allowedOrigins;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;

    }

    @Data
    public static class WebSocketConfig {

        private String path;

    }

    @Data
    public static class StaticConfig {

        private String webRoot;

    }

    @Data
    public static class LoggingConfig {

        private String level;

    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CertificateConfig {

        private String certsPath;
        private String caCertPath;
        private int keySize;
        private String keyFactoryType;
        private String signatureAlgorithm;
        private String keystorePassword;
        private int caValidityYears;
        private int userValidityYears;

    }

}
