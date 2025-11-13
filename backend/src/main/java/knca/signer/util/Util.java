package knca.signer.util;

import io.vertx.core.json.JsonObject;
import knca.signer.config.ApplicationConfig;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.lang.reflect.Field;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Util {

    public static final char[] DIGITS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final String CONFIG_PACKAGE_PREFIX = "knca.signer.config";
    private static final String ENV_VAR_PREFIX = "APP_";

    public static ApplicationConfig createApplicationConfigFromEnv() {
        JsonObject root = new JsonObject();
        Map<String, String> envToProperty = getEnvVarToPropertyMap();

        System.getenv().forEach((key, value) -> {
            String property = envToProperty.get(key);
            if (property != null) {
                buildNestedStructure(root, property, parseValue(value));
            }
        });

        return root.mapTo(ApplicationConfig.class);
    }

    private static void buildNestedStructure(JsonObject root, String property, Object value) {
        String[] parts = property.split("\\.");
        JsonObject current = root;

        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            if (part.isEmpty()) continue;

            Object existing = current.getValue(part);
            if (!(existing instanceof JsonObject)) {
                existing = new JsonObject();
                current.put(part, existing);
            }
            current = (JsonObject) existing;
        }

        String finalKey = parts[parts.length - 1];
        if (!finalKey.isEmpty()) {
            current.put(finalKey, value);
        }
    }

    private static Object parseValue(String value) {
        if (value.matches("-?\\d+")) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                return value;
            }
        }
        if (value.matches("-?\\d+\\.\\d+")) {
            try {
                return Double.parseDouble(value);
            } catch (NumberFormatException e) {
                return value;
            }
        }
        return value;
    }

    private static Map<String, String> getEnvVarToPropertyMap() {
        Map<String, String> result = new HashMap<>();
        extractFieldPaths("", ApplicationConfig.class, result);
        return result;
    }

    private static void extractFieldPaths(String prefix, Class<?> clazz, Map<String, String> result) {
        for (Field field : clazz.getDeclaredFields()) {
            Class<?> fieldType = field.getType();
            String currentPath = prefix.isEmpty() ? field.getName() : "%s.%s".formatted(prefix, field.getName());

            if (isConfigClass(fieldType)) {
                extractFieldPaths(currentPath, fieldType, result);
            } else {
                result.put(convertPropertyToEnvVar(currentPath), currentPath);
            }
        }
    }

    private static boolean isConfigClass(Class<?> clazz) {
        Package pkg = clazz.getPackage();
        return pkg != null && pkg.getName().startsWith(CONFIG_PACKAGE_PREFIX);
    }

    private static String convertPropertyToEnvVar(String propertyPath) {
        return "%s%s".formatted(ENV_VAR_PREFIX, propertyPath.toUpperCase().replace(".", "_"));
    }

    public static LocalDateTime toLocalDateTime(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    public static String encodeStr(byte[] aInput) {
        if (aInput == null) return null;

        StringBuilder result = new StringBuilder(aInput.length * 2);

        for (byte b : aInput) {
            result.append(DIGITS[(b & 240) >> 4])
                    .append(DIGITS[b & 15]);
        }

        return result.toString();
    }

}