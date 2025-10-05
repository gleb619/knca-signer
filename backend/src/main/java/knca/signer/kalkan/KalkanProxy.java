package knca.signer.kalkan;

import lombok.*;

/**
 * Interface for dynamic proxies that wrap Kalkan cryptographic library objects.
 * Provides debugging capabilities and seamless method delegation to the underlying real object.
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
            throw new RuntimeException("Invoke failed", e);
        }
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

    /**
     * Delegates equals comparison to the real object.
     * Note: This is implemented via ByteBuddy interception in the proxy class.
     *
     * @param obj the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    boolean equals(Object obj);

    /**
     * Delegates hash code calculation to the real object.
     * Note: This is implemented via ByteBuddy interception in the proxy class.
     *
     * @return the hash code of the real object
     */
    int hashCode();

    /**
     * Returns a string representation showing both proxy type and real object details.
     * Note: This is implemented via ByteBuddy interception in the proxy class.
     *
     * @return a debug-friendly string representation
     */
    String toString();

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    class ProxyArg {

        private String className;
        private String methodName;
        private Class<?>[] paramTypes;
        private Object[] args;

    }



}
