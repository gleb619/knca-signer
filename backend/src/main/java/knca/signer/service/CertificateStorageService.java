package knca.signer.service;

import knca.signer.service.CertificateService.CertificateData;
import knca.signer.service.CertificateService.CertificateResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Service for managing certificate storage and retrieval operations.
 * Handles all certificate loading, storage, and accessor methods.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateStorageService {

    private final CertificateStorage certificateStorage;

    /**
     * Get CA certificates map (deprecated - use getCACertificate or getCACertificateAliases).
     *
     * @deprecated Use encapsulated accessors instead
     */
    @Deprecated
    public Map<String, CertificateResult> getCaCertificatesMap() {
        return certificateStorage.getCaCertificates();
    }

    /**
     * Get user certificates map (deprecated - use getUserCertificate or getUserCertificateAliases).
     *
     * @deprecated Use encapsulated accessors instead
     */
    @Deprecated
    public Map<String, CertificateData> getUserCertificatesMap() {
        return certificateStorage.getUserCertificates();
    }

    /**
     * Get legal certificates map (deprecated - use getLegalCertificate or getLegalCertificateAliases).
     *
     * @deprecated Use encapsulated accessors instead
     */
    @Deprecated
    public Map<String, CertificateData> getLegalCertificatesMap() {
        return certificateStorage.getLegalCertificates();
    }

    /**
     * Get user keys map (deprecated - use getUserKey).
     *
     * @deprecated Use encapsulated accessors instead
     */
    @Deprecated
    public Map<String, java.security.KeyPair> getUserKeysMap() {
        return certificateStorage.getUserKeys();
    }

    /**
     * Get legal keys map (deprecated - use getLegalKey).
     *
     * @deprecated Use encapsulated accessors instead
     */
    @Deprecated
    public Map<String, java.security.KeyPair> getLegalKeysMap() {
        return certificateStorage.getLegalKeys();
    }

    /**
     * Get all certificates as a unified map.
     */
    public Map<String, CertificateData> getCertificates() {
        Map<String, CertificateData> certs = new HashMap<>();
        // Add all CA certificates
        certificateStorage.getCaCertificates().forEach((alias, result) ->
                certs.put("ca-" + alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        // Add all user certificates
        certificateStorage.getUserCertificates().forEach((alias, data) -> certs.put("user-" + alias, data));
        // Add all legal certificates
        certificateStorage.getLegalCertificates().forEach((alias, data) -> certs.put("legal-" + alias, data));
        return certs;
    }

    /**
     * Get all CA certificates.
     */
    public Map<String, CertificateData> getCACertificates() {
        Map<String, CertificateData> cas = new HashMap<>();
        certificateStorage.getCaCertificates().forEach((alias, result) ->
                cas.put(alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        return cas;
    }

    /**
     * Get all user certificates.
     */
    public Map<String, CertificateData> getUserCertificates() {
        return new HashMap<>(certificateStorage.getUserCertificates());
    }

    /**
     * Get all legal certificates.
     */
    public Map<String, CertificateData> getLegalCertificates() {
        return new HashMap<>(certificateStorage.getLegalCertificates());
    }

    /**
     * Store a new user certificate and its key.
     */
    public void storeUserCertificate(String alias, CertificateData data, java.security.KeyPair keyPair) {
        if (Objects.nonNull(keyPair)) {
            certificateStorage.getUserKeys().put(alias, keyPair);
        }
        certificateStorage.getUserCertificates().put(alias, data);
    }

    /**
     * Store a new legal certificate and its key.
     */
    public void storeLegalCertificate(String alias, CertificateData data, java.security.KeyPair keyPair) {
        if (Objects.nonNull(keyPair)) {
            certificateStorage.getLegalKeys().put(alias, keyPair);
        }
        certificateStorage.getLegalCertificates().put(alias, data);
    }

    /**
     * Store a new CA certificate.
     */
    public void storeCACertificate(String alias, CertificateResult result) {
        certificateStorage.getCaCertificates().put(alias, result);
    }

    /**
     * Get CA certificate by alias.
     */
    public java.util.Optional<CertificateResult> getCACertificate(String alias) {
        return java.util.Optional.ofNullable(certificateStorage.getCaCertificates().get(alias));
    }

    /**
     * Add CA certificate.
     */
    public void addCACertificate(String alias, CertificateResult result) {
        certificateStorage.getCaCertificates().put(alias, result);
    }

    /**
     * Remove CA certificate.
     */
    public boolean removeCACertificate(String alias) {
        return certificateStorage.getCaCertificates().remove(alias) != null;
    }

    /**
     * Check if CA certificate exists.
     */
    public boolean hasCACertificate(String alias) {
        return certificateStorage.getCaCertificates().containsKey(alias);
    }

    /**
     * Get all CA certificate aliases.
     */
    public java.util.Set<String> getCACertificateAliases() {
        return new java.util.HashSet<>(certificateStorage.getCaCertificates().keySet());
    }

    /**
     * Get user certificate by alias.
     */
    public java.util.Optional<CertificateData> getUserCertificate(String alias) {
        return java.util.Optional.ofNullable(certificateStorage.getUserCertificates().get(alias));
    }

    /**
     * Add user certificate and optionally its key.
     */
    public void addUserCertificate(String alias, CertificateData data, java.security.KeyPair keyPair) {
        certificateStorage.getUserCertificates().put(alias, data);
        if (keyPair != null) {
            certificateStorage.getUserKeys().put(alias, keyPair);
        }
    }

    /**
     * Remove user certificate and its key.
     */
    public boolean removeUserCertificate(String alias) {
        certificateStorage.getUserCertificates().remove(alias);
        return certificateStorage.getUserKeys().remove(alias) != null;
    }

    /**
     * Check if user certificate exists.
     */
    public boolean hasUserCertificate(String alias) {
        return certificateStorage.getUserCertificates().containsKey(alias);
    }

    /**
     * Get all user certificate aliases.
     */
    public java.util.Set<String> getUserCertificateAliases() {
        return new java.util.HashSet<>(certificateStorage.getUserCertificates().keySet());
    }

    /**
     * Get user key by alias.
     */
    public java.util.Optional<java.security.KeyPair> getUserKey(String alias) {
        return java.util.Optional.ofNullable(certificateStorage.getUserKeys().get(alias));
    }

    /**
     * Get legal certificate by alias.
     */
    public java.util.Optional<CertificateData> getLegalCertificate(String alias) {
        return java.util.Optional.ofNullable(certificateStorage.getLegalCertificates().get(alias));
    }

    /**
     * Add legal certificate and optionally its key.
     */
    public void addLegalCertificate(String alias, CertificateData data, java.security.KeyPair keyPair) {
        certificateStorage.getLegalCertificates().put(alias, data);
        if (keyPair != null) {
            certificateStorage.getLegalKeys().put(alias, keyPair);
        }
    }

    /**
     * Remove legal certificate and its key.
     */
    public boolean removeLegalCertificate(String alias) {
        certificateStorage.getLegalCertificates().remove(alias);
        return certificateStorage.getLegalKeys().remove(alias) != null;
    }

    /**
     * Check if legal certificate exists.
     */
    public boolean hasLegalCertificate(String alias) {
        return certificateStorage.getLegalCertificates().containsKey(alias);
    }

    /**
     * Get all legal certificate aliases.
     */
    public java.util.Set<String> getLegalCertificateAliases() {
        return new java.util.HashSet<>(certificateStorage.getLegalCertificates().keySet());
    }

    /**
     * Get legal key by alias.
     */
    public java.util.Optional<java.security.KeyPair> getLegalKey(String alias) {
        return java.util.Optional.ofNullable(certificateStorage.getLegalKeys().get(alias));
    }

    /**
     * Get private key for the first user certificate (backward compatibility).
     */
    public java.util.Optional<java.security.PrivateKey> getFirstUserPrivateKey() {
        return certificateStorage.getUserKeys().values().stream().findFirst().map(java.security.KeyPair::getPrivate);
    }

    /**
     * Get first CA certificate (backward compatibility).
     */
    public java.util.Optional<CertificateResult> getFirstCACertificate() {
        return certificateStorage.getCaCertificates().values().stream().findFirst();
    }

    /**
     * Get private key for the first legal certificate (backward compatibility).
     */
    public java.util.Optional<java.security.PrivateKey> getFirstLegalPrivateKey() {
        return certificateStorage.getLegalKeys().values().stream().findFirst().map(java.security.KeyPair::getPrivate);
    }

    /**
     * Get filesystem certificates.
     */
    public List<CertificateReader.CertificateInfo> getFilesystemCertificates() {
        return new ArrayList<>(certificateStorage.getFilesystemCertificates());
    }

    /**
     * Add filesystem certificate.
     */
    public void addFilesystemCertificate(CertificateReader.CertificateInfo cert) {
        certificateStorage.getFilesystemCertificates().add(cert);
    }

    /**
     * Clear filesystem certificates.
     */
    public void clearFilesystemCertificates() {
        certificateStorage.getFilesystemCertificates().clear();
    }

    @lombok.Value
    public static class CertificateStorage {
        Map<String, CertificateResult> caCertificates = new ConcurrentHashMap<>();
        Map<String, java.security.KeyPair> userKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> userCertificates = new ConcurrentHashMap<>();
        Map<String, java.security.KeyPair> legalKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> legalCertificates = new ConcurrentHashMap<>();
        java.util.Queue<CertificateReader.CertificateInfo> filesystemCertificates = new ConcurrentLinkedQueue<>();
    }
}
