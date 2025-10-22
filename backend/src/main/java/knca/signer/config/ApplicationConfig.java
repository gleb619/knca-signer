package knca.signer.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

/**
 * Application configuration holder
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
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

        @JsonSetter("allowedMethods")
        public void setAllowedMethods(Object o) {
            if (o instanceof String s) {
                this.allowedMethods = Arrays.asList(s.split("\\s*,\\s*"));
            } else if (o instanceof List<?> l) {
                this.allowedMethods = (List<String>) l;
            }
        }

        @JsonSetter("allowedHeaders")
        public void setAllowedHeaders(Object o) {
            if (o instanceof String s) {
                this.allowedHeaders = Arrays.asList(s.split("\\s*,\\s*"));
            } else if (o instanceof List<?> l) {
                this.allowedHeaders = (List<String>) l;
            }
        }

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

        private String storageMode;
        private int initialUserCertificates;
        private int initialLegalCertificates;
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
