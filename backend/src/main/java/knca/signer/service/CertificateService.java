package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.controller.VerifierHandler.XmlValidationRequest;
import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanException;
import knca.signer.util.XmlUtil;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CertificateService {

    private final Provider provider;
    private final ApplicationConfig.CertificateConfig config;
    private final CertificateStorage storage;
    private final CertificateGenerator generationService;
    private final CertificateValidator validationService;

    public CertificateService init() {
        try {
            generationService.init();
        } catch (Exception e) {
            if (e instanceof KalkanException ke) {
                throw ke;
            } else {
                throw new RuntimeException("Failed to init CertificateService", e);
            }
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

    /**
     * Sign XML content using certificate alias. Behavior depends on storageMode:
     * - "in-memory": uses keystore lookup
     * - "file": uses PEM files from certsPath
     *
     * @param xmlData   The XML content to sign
     * @param certAlias The certificate alias (e.g., "user", "legal")
     * @return The signed XML as a string
     * @throws Exception If signing fails
     */
    public String signXml(String xmlData, String certAlias) throws Exception {
        if ("file".equals(config.getStorageMode())) {
            // File mode: use PEM files
            String certPemPath = "%s%s.crt".formatted(config.getCertsPath(), certAlias);
            String keyPemPath = "%s%s.key".formatted(config.getCertsPath(), certAlias);
            return signXmlWithPemFiles(xmlData, certPemPath, keyPemPath);
        } else {
            // In-memory mode: use keystore lookup
            X509Certificate certificate = getCertificate(certAlias);
            PrivateKey privateKey = getPrivateKey(certAlias);

            // Create certificate chain including CA certificate
            List<X509Certificate> certificateChain;
            if (storage.hasCACertificate(certAlias)) {
                // CA certificate - self-signed
                certificateChain = List.of(certificate);
            } else {
                // User or legal certificate - include CA certificate
                CertificateData certData = storage.getUserCertificate(certAlias).orElse(null);
                if (certData == null) {
                    certData = storage.getLegalCertificate(certAlias).orElse(null);
                }
                if (certData != null) {
                    String caId = certData.getCaId();
                    X509Certificate caCert = storage.getCACertificate(caId).orElseThrow().getCertificate();
                    certificateChain = List.of(certificate, caCert);
                } else {
                    certificateChain = List.of(certificate);
                }
            }

            SigningEntity signingEntity = new SigningEntity(privateKey, certificateChain);
            try {
                return XmlUtil.createXmlSignature(signingEntity, xmlData);
            } catch (MarshalException | XMLSignatureException |
                     NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                throw new Exception("XML signing failed: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Sign XML content using certificate and private key from PEM files.
     *
     * @param xmlData     The XML content to sign
     * @param certPemPath Path to certificate PEM file
     * @param keyPemPath  Path to private key PEM file
     * @return The signed XML as a string
     * @throws Exception If signing fails
     */
    public String signXmlWithPemFiles(String xmlData, String certPemPath, String keyPemPath) throws Exception {
        CertificateReader reader = new CertificateReader(config);
        CertificateReader.PemSigningData pemData = reader.loadPemSigningData(certPemPath, keyPemPath, provider.getName());

        List<X509Certificate> certificateChain = List.of(pemData.certificate);
        SigningEntity signingEntity = new SigningEntity(pemData.privateKey, certificateChain);
        try {
            return XmlUtil.createXmlSignature(signingEntity, xmlData);
        } catch (MarshalException | XMLSignatureException |
                 NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new Exception("XML signing failed: " + e.getMessage(), e);
        }
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
            filename = "ca-%s.%s".formatted(alias, format);
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
                filename = "%s.%s".formatted(alias, format);
            } else {
                log.warn("Certificate not found: {}", alias);
                return null;
            }
        }

        // Generate file content based on format
        byte[] data = switch (format.toLowerCase()) {
            case "crt", "pem" ->
                // Generate PEM certificate
                    generatePemCertificate(cert);
            case "p12" ->
                // Generate PKCS12 keystore
                    generatePKCS12Keystore(privateKey, cert, caCert);
            case "jks" ->
                // Generate JKS keystore
                    generateJKSKeystore(privateKey, cert, caCert);
            default -> throw new IllegalArgumentException("Unsupported format: " + format);
        };

        return new CertificateDownloadData(filename, data);
    }

    @SneakyThrows
    private byte[] generatePemCertificate(X509Certificate cert) {
        // Use existing PEM writing logic from CertificateGenerator
        StringWriter stringWriter = new StringWriter();
        var pemWriter = KalkanAdapter.createPEMWriter(stringWriter);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        return stringWriter.toString().getBytes(StandardCharsets.UTF_8);
    }

    @SneakyThrows
    private byte[] generatePKCS12Keystore(PrivateKey privateKey, X509Certificate cert, X509Certificate caCert) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        KeyStore keyStore = KeyStore.getInstance("PKCS12", provider.getName());
        keyStore.load(null, null);

        Certificate[] chain = new Certificate[]{cert, caCert};
        keyStore.setKeyEntry("user", privateKey, config.getKeystorePassword().toCharArray(), chain);

        keyStore.store(baos, config.getKeystorePassword().toCharArray());
        return baos.toByteArray();
    }

    @SneakyThrows
    private byte[] generateJKSKeystore(PrivateKey privateKey, X509Certificate cert, X509Certificate caCert) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        Certificate[] chain = new Certificate[]{cert, caCert};
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
    @Data
    @RequiredArgsConstructor
    public static class CertificateResult {
        private final KeyPair keyPair;
        private final X509Certificate certificate;
    }

    @Data
    @RequiredArgsConstructor
    public static class CertificateData {
        private final String email;
        private final String iin;
        private final String bin;
        private final String caId;
        private final X509Certificate certificate;
    }

    @Builder
    @Data
    @AllArgsConstructor
    @NoArgsConstructor(access = AccessLevel.PUBLIC)
    public static class ValidationDetail {
        private String key;        // e.g., "signature", "dataIntegrity", "certificateIin"
        private String type;       // e.g., "check", "extraction", "error"
        private String status;     // e.g., "passed", "failed", "not_applicable"
        private String value;      // for extractions like IIN/BIN values
        private String message;    // optional translated message or error details
    }

    @Data
    @AllArgsConstructor
    public static class ValidationResult {
        private boolean valid;
        private String code;
        private String message;
        private List<ValidationDetail> details;
    }

    @Data
    @AllArgsConstructor
    public static class SignedData {
        private final String originalData;
        private final String signature;
        private final String certAlias;

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

    @Data
    @AllArgsConstructor
    public static class CertificateDownloadData {
        private final String filename;
        private final byte[] data;
    }

    /**
     * Represents the signing entity containing private key and certificate chain.
     * Used for creating digital signatures across different formats (XML, CMS, raw).
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SigningEntity {

        /**
         * The private key used for signing
         */
        private PrivateKey key;

        /**
         * The certificate chain, where the first certificate is the signing certificate
         */
        private List<X509Certificate> certificateChain;

        /**
         * Get the signing certificate (first in chain)
         */
        public X509Certificate getCertificate() {
            return certificateChain != null && !certificateChain.isEmpty()
                    ? certificateChain.getFirst()
                    : null;
        }

    }


}
