package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.controller.VerifierHandler.XmlValidationRequest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CertificateService {

    private final java.security.Provider provider;
    private final ApplicationConfig.CertificateConfig config;
    private final CertificateStorage storage;
    private final CertificateGenerator generationService;
    private final CertificateValidator validationService;

    public CertificateService init() {
        try {
            generationService.init();
        } catch (Exception e) {
            throw new RuntimeException("Failed to init CertificateService", e);
        }
        return this;
    }

    public String signData(String data, String certAlias) throws Exception {
        PrivateKey privateKey = getPrivateKey(certAlias);
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(privateKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public SignedData signDataWithResult(String data, String certAlias) throws Exception {
        String signature = signData(data, certAlias);
        return new SignedData(data, signature, certAlias);
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateUserCertificate(String caId) {
        return generationService.generateUserCertificate(caId);
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateLegalEntityCertificate(String caId) {
        return generationService.generateLegalEntityCertificate(caId);
    }

    public Map.Entry<String, CertificateResult> generateCACertificate(String alias) throws Exception {
        return generationService.generateCACertificate(alias);
    }

    public ValidationResult validateXmlSignature(XmlValidationRequest request) throws Exception {
        return validationService.validateXmlSignature(request);
    }

    public List<CertificateReader.CertificateInfo> getFilesystemCertificates() {
        return storage.getFilesystemCertificates();
    }

    /**
     * Download certificate in the specified format.
     *
     * @param alias  Certificate alias
     * @param format Format: crt, pem, p12, jks
     * @return CertificateDownloadData with filename and binary data, or null if not found
     */
    @SneakyThrows
    public CertificateDownloadData downloadCertificate(String alias, String format) {
        // TODO: This could be moved to a separate service if needed
        log.info("Generating download data for certificate {} in format {}", alias, format);

        // Find the certificate: could be CA, user, or legal
        X509Certificate cert;
        try {
            cert = getCertificate(alias);
        } catch (IllegalArgumentException e) {
            return null;
        }

        X509Certificate caCert = null;
        PrivateKey privateKey = null;
        String filename;

        // Try to find certificate in different stores
        if (storage.hasCACertificate(alias)) {
            // CA certificate
            var caResult = storage.getCACertificate(alias).orElseThrow();
            caCert = cert; // Self-signed CA
            privateKey = caResult.getKeyPair().getPrivate();
            filename = alias + "." + format;
        } else {
            // User or legal certificate - need to find CA cert and private key
            CertificateData certData = storage.getUserCertificate(alias).orElse(null);
            if (certData == null) {
                certData = storage.getLegalCertificate(alias).orElse(null);
            }
            if (certData != null) {
                String caAlias = certData.getCaId();
                caCert = storage.getCACertificate(caAlias).orElseThrow().getCertificate();
                privateKey = storage.getUserKey(alias)
                        .orElseGet(() -> storage.getLegalKey(alias).orElse(null))
                        .getPrivate();
                filename = alias + "." + format;
            } else {
                log.warn("Certificate not found: {}", alias);
                return null;
            }
        }

        // Generate file content based on format
        byte[] data;
        switch (format.toLowerCase()) {
            case "crt":
            case "pem":
                // Generate PEM certificate
                data = generatePemCertificate(cert);
                break;
            case "p12":
                // Generate PKCS12 keystore
                data = generatePKCS12Keystore(privateKey, cert, caCert);
                break;
            case "jks":
                // Generate JKS keystore
                data = generateJKSKeystore(privateKey, cert, caCert);
                break;
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }

        return new CertificateDownloadData(filename, data);
    }

    @SneakyThrows
    private byte[] generatePemCertificate(X509Certificate cert) {
        // Use existing PEM writing logic from CertificateGenerator
        java.io.StringWriter stringWriter = new java.io.StringWriter();
        var kalkanProxy = knca.signer.kalkan.KalkanAdapter.createPEMWriter(stringWriter);
        knca.signer.kalkan.KalkanAdapter.writeObject(kalkanProxy, cert);
        knca.signer.kalkan.KalkanAdapter.flush(kalkanProxy);
        return stringWriter.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    @SneakyThrows
    private byte[] generatePKCS12Keystore(PrivateKey privateKey, X509Certificate cert, X509Certificate caCert) {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12", provider.getName());
        keyStore.load(null, null);

        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{cert, caCert};
        keyStore.setKeyEntry("user", privateKey, config.getKeystorePassword().toCharArray(), chain);

        keyStore.store(baos, config.getKeystorePassword().toCharArray());
        return baos.toByteArray();
    }

    @SneakyThrows
    private byte[] generateJKSKeystore(PrivateKey privateKey, X509Certificate cert, X509Certificate caCert) {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{cert, caCert};
        keyStore.setKeyEntry("user", privateKey, config.getKeystorePassword().toCharArray(), chain);

        keyStore.store(baos, config.getKeystorePassword().toCharArray());
        return baos.toByteArray();
    }

    public X509Certificate getCertificate(String alias) {
        if (storage.hasUserCertificate(alias)) {
            return storage.getUserCertificate(alias).orElseThrow().getCertificate();
        }
        if (storage.hasLegalCertificate(alias)) {
            return storage.getLegalCertificate(alias).orElseThrow().getCertificate();
        }
        if (storage.hasCACertificate(alias)) {
            return storage.getCACertificate(alias).orElseThrow().getCertificate();
        }
        // For backward compatibility
        if ("user".equals(alias) && !storage.getUserCertificates().isEmpty()) {
            return storage.getUserCertificates().values().iterator().next().getCertificate();
        }
        if ("legal".equals(alias) && !storage.getLegalCertificates().isEmpty()) {
            return storage.getLegalCertificates().values().iterator().next().getCertificate();
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    private PrivateKey getPrivateKey(String alias) {
        if (storage.getUserKey(alias).isPresent()) {
            return storage.getUserKey(alias).orElseThrow().getPrivate();
        }
        if (storage.getLegalKey(alias).isPresent()) {
            return storage.getLegalKey(alias).orElseThrow().getPrivate();
        }
        // For backward compatibility
        if ("user".equals(alias)) {
            return storage.getFirstUserPrivateKey().orElseThrow(() ->
                    new IllegalArgumentException("No user certificate found"));
        }
        if ("legal".equals(alias)) {
            return storage.getFirstLegalPrivateKey().orElseThrow(() ->
                    new IllegalArgumentException("No legal certificate found"));
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    // Nested classes for backward compatibility
    @lombok.Data
    @lombok.RequiredArgsConstructor
    public static class CertificateResult {
        private final java.security.KeyPair keyPair;
        private final java.security.cert.X509Certificate certificate;
    }

    @lombok.Data
    @lombok.RequiredArgsConstructor
    public static class CertificateData {
        private final String email;
        private final String iin;
        private final String bin;
        private final String caId;
        private final java.security.cert.X509Certificate certificate;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class ValidationResult {
        private boolean valid;
        private String message;
        private Map<String, String> details;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class SignedData {
        private final String originalData;
        private final String signature;
        private final String certAlias;

        public String getSignedContent() {
            return originalData + signature;
        }

        public String getFormattedSignedContent() {
            return String.format("<content><data>%s</data><signature>%s</signature><alias>%s</alias></content>",
                    escapeXml(originalData), escapeXml(signature), escapeXml(certAlias));
        }

        private String escapeXml(String s) {
            return s.replaceAll("&", "&")
                    .replaceAll(">", ">")
                    .replaceAll("<", "<")
                    .replaceAll("\\\"", "\"")
                    .replaceAll("'", "'");
        }
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class CertificateDownloadData {
        private final String filename;
        private final byte[] data;
    }
}
