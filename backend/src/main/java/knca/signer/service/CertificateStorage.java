package knca.signer.service;

import knca.signer.service.CertificateReader.CertificateInfo;
import knca.signer.service.CertificateService.CertificateData;
import knca.signer.service.CertificateService.CertificateResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Service for managing certificate storage and retrieval operations.
 * Handles all certificate loading, storage, and accessor methods.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateStorage {

    private final Storage storage;

    /**
     * Set shared company info for legal certificates of a CA.
     */
    public void setLegalCompanyInfo(String caAlias, String company, String bin) {
        storage.getLegalCompanyInfos().put(caAlias, new LegalCompanyInfo(company, bin));
    }

    /**
     * Get shared company info for legal certificates of a CA.
     */
    public Optional<LegalCompanyInfo> getLegalCompanyInfo(String caAlias) {
        return Optional.ofNullable(storage.getLegalCompanyInfos().get(caAlias));
    }

    /**
     * Get filesystem certificates.
     */
    @Deprecated(forRemoval = true)
    public List<CertificateInfo> getFilesystemCertificates() {
        return new ArrayList<>(storage.getFilesystemCertificates());
    }


    /**
     * Get all certificates as a unified map.
     */
    public Map<String, CertificateData> getCertificates() {
        Map<String, CertificateData> certs = new HashMap<>();
        // Add all CA certificates
        storage.getCaCertificates().forEach((alias, result) ->
                certs.put("ca-%s".formatted(alias), new CertificateData(null, null, null, alias, result.getCertificate())));
        // Add all user certificates
        storage.getUserCertificates().forEach((alias, data) -> certs.put("user-" + alias, data));
        // Add all legal certificates
        storage.getLegalCertificates().forEach((alias, data) -> certs.put("legal-" + alias, data));
        return certs;
    }

    /**
     * Get all CA certificates.
     */
    public Map<String, CertificateData> getCACertificates() {
        Map<String, CertificateData> cas = new HashMap<>();
        storage.getCaCertificates().forEach((alias, result) ->
                cas.put(alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        return cas;
    }

    /**
     * Get all user certificates.
     */
    public Map<String, CertificateData> getUserCertificates() {
        return new HashMap<>(storage.getUserCertificates());
    }

    /**
     * Get all legal certificates.
     */
    public Map<String, CertificateData> getLegalCertificates() {
        return new HashMap<>(storage.getLegalCertificates());
    }

    /**
     * Store a new user certificate and its key.
     */
    public void storeUserCertificate(String alias, CertificateData data, KeyPair keyPair) {
        if (Objects.nonNull(keyPair)) {
            storage.getUserKeys().put(alias, keyPair);
        }
        storage.getUserCertificates().put(alias, data);
    }

    /**
     * Store a new legal certificate and its key.
     */
    public void storeLegalCertificate(String alias, CertificateData data, KeyPair keyPair) {
        if (Objects.nonNull(keyPair)) {
            storage.getLegalKeys().put(alias, keyPair);
        }
        storage.getLegalCertificates().put(alias, data);
    }

    /**
     * Store a new CA certificate.
     */
    public void storeCACertificate(String alias, CertificateResult result) {
        storage.getCaCertificates().put(alias, result);
    }

    /**
     * Get CA certificate by alias.
     */
    public Optional<CertificateResult> getCACertificate(String alias) {
        return Optional.ofNullable(storage.getCaCertificates().get(alias));
    }

    /**
     * Check if CA certificate exists.
     */
    public boolean hasCACertificate(String alias) {
        return storage.getCaCertificates().containsKey(alias);
    }

    /**
     * Get all CA certificate aliases.
     */
    public Set<String> getCACertificateAliases() {
        return new HashSet<>(storage.getCaCertificates().keySet());
    }

    /**
     * Get user certificate by alias.
     */
    public Optional<CertificateData> getUserCertificate(String alias) {
        return Optional.ofNullable(storage.getUserCertificates().get(alias));
    }

    /**
     * Add user certificate and optionally its key.
     */
    public void addUserCertificate(String alias, CertificateData data, KeyPair keyPair) {
        storage.getUserCertificates().put(alias, data);
        if (keyPair != null) {
            storage.getUserKeys().put(alias, keyPair);
        }
    }

    /**
     * Check if user certificate exists.
     */
    public boolean hasUserCertificate(String alias) {
        return storage.getUserCertificates().containsKey(alias);
    }

    /**
     * Get user key by alias.
     */
    public Optional<KeyPair> getUserKey(String alias) {
        return Optional.ofNullable(storage.getUserKeys().get(alias));
    }

    /**
     * Get legal certificate by alias.
     */
    public Optional<CertificateData> getLegalCertificate(String alias) {
        return Optional.ofNullable(storage.getLegalCertificates().get(alias));
    }

    /**
     * Add legal certificate and optionally its key.
     */
    public void addLegalCertificate(String alias, CertificateData data, KeyPair keyPair) {
        storage.getLegalCertificates().put(alias, data);
        if (keyPair != null) {
            storage.getLegalKeys().put(alias, keyPair);
        }
    }

    /**
     * Check if legal certificate exists.
     */
    public boolean hasLegalCertificate(String alias) {
        return storage.getLegalCertificates().containsKey(alias);
    }

    /**
     * Get legal key by alias.
     */
    public Optional<KeyPair> getLegalKey(String alias) {
        return Optional.ofNullable(storage.getLegalKeys().get(alias));
    }

    /**
     * Get private key for the first user certificate (backward compatibility).
     */
    public Optional<PrivateKey> getFirstUserPrivateKey() {
        return storage.getUserKeys().values().stream().findFirst().map(KeyPair::getPrivate);
    }

    /**
     * Get first CA certificate (backward compatibility).
     */
    public Optional<CertificateResult> getFirstCACertificate() {
        return storage.getCaCertificates().values().stream().findFirst();
    }

    /**
     * Get private key for the first legal certificate (backward compatibility).
     */
    public Optional<PrivateKey> getFirstLegalPrivateKey() {
        return storage.getLegalKeys().values().stream().findFirst().map(KeyPair::getPrivate);
    }

    /**
     * Record for legal company information.
     */
    public record LegalCompanyInfo(String company, String bin) {
    }

    /**
     * Add filesystem certificate.
     */
    public void addFilesystemCertificate(CertificateInfo cert) {
        storage.getFilesystemCertificates().add(cert);
    }

    /**
     * Clear filesystem certificates.
     */
    public void clearFilesystemCertificates() {
        storage.getFilesystemCertificates().clear();
    }

    @lombok.Value
    public static class Storage {

        Map<String, CertificateResult> caCertificates = new ConcurrentHashMap<>();
        Map<String, KeyPair> userKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> userCertificates = new ConcurrentHashMap<>();
        Map<String, KeyPair> legalKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> legalCertificates = new ConcurrentHashMap<>();
        Map<String, LegalCompanyInfo> legalCompanyInfos = new ConcurrentHashMap<>();
        @Deprecated(forRemoval = true)
        Queue<CertificateInfo> filesystemCertificates = new ConcurrentLinkedQueue<>();

    }
}
