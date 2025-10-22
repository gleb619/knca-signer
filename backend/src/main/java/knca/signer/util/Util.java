package knca.signer.util;

import io.vertx.core.json.JsonObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Util {

    /**
     * Convert environment variables to nested JSON structure for configuration override.
     * Converts UPPER_UNDERSCORE format to nested lower.case.dot format.
     *
     * @return JsonObject containing nested environment variable structure
     */
    public static JsonObject flattenEnvironmentVariables() {
        JsonObject root = new JsonObject();

        System.getenv().forEach((key, value) -> {
            // Convert UPPER_UNDERSCORE format to lower.dot.case format
            String flattenedKey = key.toLowerCase().replace('_', '.');

            // Split the key into parts for nesting, filter out empty parts
            String[] parts = flattenedKey.split("\\.");
            java.util.List<String> filteredParts = new java.util.ArrayList<>();
            for (String part : parts) {
                if (!part.isEmpty()) {
                    filteredParts.add(part);
                }
            }

            if (filteredParts.isEmpty()) {
                // Skip invalid env vars that result in empty keys
                return;
            }

            // Try to parse as number if possible, otherwise keep as string
            Object parsedValue = parseValue(value);

            // Build nested structure
            JsonObject current = root;
            for (int i = 0; i < filteredParts.size() - 1; i++) {
                String part = filteredParts.get(i);
                Object existing = current.getValue(part);
                JsonObject next;
                if (existing == null) {
                    next = new JsonObject();
                    current.put(part, next);
                } else if (existing instanceof JsonObject) {
                    next = (JsonObject) existing;
                } else {
                    // Conflict: existing value is not a JsonObject, replace it
                    next = new JsonObject();
                    current.put(part, next);
                }
                current = next;
            }

            // Set the final value
            String finalKey = filteredParts.get(filteredParts.size() - 1);
            current.put(finalKey, parsedValue);
        });

        return root;
    }

    /**
     * Parse string value to appropriate type (number or string).
     */
    public static Object parseValue(String value) {
        // Try to parse as number if possible, otherwise keep as string
        try {
            if (value.matches("-?\\d+(\\.\\d+)?")) {
                if (value.contains(".")) {
                    return Double.parseDouble(value);
                } else {
                    return Long.parseLong(value);
                }
            }
        } catch (NumberFormatException e) {
            // Keep as string if not a valid number
            return value;
        }
        return value;
    }

}
