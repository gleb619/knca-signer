package knca.signer.kalkan;

import lombok.*;

/**
 * Interface for dynamic proxies that wrap Kalkan cryptographic library objects.
 * Uses high-performance MVEL scripting engine for optimized method dispatching,
 * providing performance benefits over traditional reflection while maintaining
 * clean separation from commercial cryptographic libraries.
 */
public interface KalkanProxy {

    /**
     * Returns the real Kalkan object that this proxy wraps.
     *
     * @return the underlying Kalkan object instance
     */
    Object getRealObject();

    /**
     * Returns the fully qualified class name of the proxied object.
     * Useful for debugging and type identification.
     *
     * @return the class name of the real object
     */
    default String getType() {
        return getRealObject().getClass().getName();
    }

    /**
     * Invokes a method on the proxied object with the given arguments.
     * Uses MVEL script execution for optimized calls when script is provided.
     *
     * @param arg the method invocation arguments
     * @return the result wrapped in a KalkanProxy
     * @throws RuntimeException if the invocation fails
     */
    default KalkanProxy invoke(ProxyArg arg) {
        try {
            Object result = ReflectionHelper.invokeMethod(getRealObject(), arg.getMethodName(), arg.getParamTypes(), arg.getArgs());
            return (KalkanProxy) KalkanRegistry.wrapValue(result);
        } catch (Exception e) {
            throw new KalkanException("Invoke failed", e);
        }
    }

    /**
     * Invokes a method on the proxied object using a MVEL script with the given arguments.
     * This method provides a way to execute dynamic scripts that can call methods on the proxied object.
     *
     * @param script the MVEL script to execute
     * @param args   the arguments to pass to the script
     * @return the result wrapped in a KalkanProxy
     */
    default KalkanProxy invokeScript(String script, Object... args) {
        return invoke(ProxyArg.script(script, args));
    }

    /**
     * Gets the result value from a proxied result.
     *
     * @return the underlying result object
     */
    default Object getResult() {
        return getRealObject();
    }

    /**
     * Gets the type of the result.
     *
     * @return the result type name
     */
    default String getResultType() {
        return getRealObject().getClass().getName();
    }

    /**
     * Casts the result to the specified type.
     *
     * @param <T> the type to cast to
     * @return the typed result
     */
    default <T> T genericValue() {
        return (T) getRealObject();
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    class ProxyArg {

        private String script;
        private String className;
        private String methodName;
        private Class<?>[] paramTypes;
        private Object[] args;

        public static ProxyArg script(String script, Object... args) {
            return ProxyArg.builder()
                    .script(script)
                    .args(args)
                    .build();
        }

    }

}
