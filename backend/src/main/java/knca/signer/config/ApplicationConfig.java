package knca.signer.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;

import java.util.Arrays;
import java.util.List;

@Data
@AllArgsConstructor
@Builder(toBuilder = true)
@NoArgsConstructor(access = AccessLevel.PUBLIC)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ApplicationConfig {

    private HttpConfig http;
    private CorsConfig cors;
    private WebSocketConfig websocket;
    private StaticConfig staticConfig;
    private LoggingConfig logging;
    private CertificateConfig certificate;

    @SneakyThrows
    public ApplicationConfig merge(ApplicationConfig overrides) {
        if (overrides == null) return this;

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);

        return mapper.convertValue(
                mapper.updateValue(mapper.valueToTree(this), overrides),
                ApplicationConfig.class
        );
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class HttpConfig {
        private int port;
        private String host;
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class CorsConfig {
        private String allowedOrigins;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;

        @JsonSetter("allowedMethods")
        public void setAllowedMethods(Object o) {
            this.allowedMethods = o instanceof String s ? Arrays.asList(s.split("\\s*,\\s*")) : (List<String>) o;
        }

        @JsonSetter("allowedHeaders")
        public void setAllowedHeaders(Object o) {
            this.allowedHeaders = o instanceof String s ? Arrays.asList(s.split("\\s*,\\s*")) : (List<String>) o;
        }
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class WebSocketConfig {
        private String path;
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class StaticConfig {
        private String webRoot;
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class LoggingConfig {
        private String level;
    }

    @Data
    @AllArgsConstructor
    @Builder(toBuilder = true)
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
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