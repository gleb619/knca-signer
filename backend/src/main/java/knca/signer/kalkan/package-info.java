/**
 * Package containing KalkanCrypt integration using reflection.
 * Due to license restrictions, Kalkan JAR files cannot be included at compile time
 * in this open-source project. Therefore, all interactions with KalkanCrypt
 * are performed through Java reflection mechanisms at runtime.
 * This approach allows the application to dynamically load and use KalkanCrypt
 * functionality without requiring the JARs as compile-time dependencies,
 * while maintaining compatibility with the NCALayer middleware.
 */
package knca.signer.kalkan;