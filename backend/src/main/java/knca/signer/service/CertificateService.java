package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.KalkanProxy;
import knca.signer.service.CertificateValidator.XmlValidator;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Stream;

@Slf4j
@RequiredArgsConstructor
public class CertificateService {

    public static final String DEFAULT_CA_ALIAS = "default";

    private final java.security.Provider provider;
    private final ApplicationConfig.CertificateConfig config;

    private final CertificateStorage certificateStorage = new CertificateStorage();

    public CertificateService init() {
        try {
            // Load or generate CA certificates
            loadOrGenerateCACertificates();

            // Load or generate user certificates for each CA
            loadOrGenerateUserCertificates();

            // Load or generate legal certificates for each CA
            loadOrGenerateLegalCertificates();

            // Load filesystem certificates for fast retrieval
            loadFilesystemCertificates();

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CertificateService", e);
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

    public boolean verifySignature(String data, String signature, String certAlias) throws Exception {
        X509Certificate cert = getCertificate(certAlias);
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initVerify(cert.getPublicKey());
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }

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

    public Map<String, CertificateData> getCACertificates() {
        Map<String, CertificateData> cas = new HashMap<>();
        certificateStorage.getCaCertificates().forEach((alias, result) ->
                cas.put(alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        return cas;
    }

    public Map<String, CertificateData> getUserCertificates() {
        return new HashMap<>(certificateStorage.getUserCertificates());
    }

    public Map<String, CertificateData> getLegalCertificates() {
        return new HashMap<>(certificateStorage.getLegalCertificates());
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateUserCertificate(String caId) {
        CertificateResult caResult = certificateStorage.getCaCertificates().get(caId);
        if (caResult == null) {
            throw new IllegalArgumentException("Unknown CA: " + caId);
        }

        String alias = "user-" + UUID.randomUUID().toString().substring(0, 8);
        String userSubjectDN = CertificateDataGenerator.generateIndividualSubjectDN();
        String email = CertificateDataGenerator.extractEmail(userSubjectDN);
        String iin = CertificateDataGenerator.extractIIN(userSubjectDN);
        String bin = CertificateDataGenerator.extractBIN(userSubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate userCert = generateUserCert(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), userSubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, userCert);
        certificateStorage.getUserKeys().put(alias, keyPair);
        certificateStorage.getUserCertificates().put(alias, data);
        return Map.entry(alias, data);
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateLegalEntityCertificate(String caId) {
        CertificateResult caResult = certificateStorage.getCaCertificates().get(caId);
        if (caResult == null) {
            throw new IllegalArgumentException("Unknown CA: " + caId);
        }

        String alias = "legal-" + UUID.randomUUID().toString().substring(0, 8);
        String legalEntitySubjectDN = CertificateDataGenerator.generateLegalEntitySubjectDN();
        String email = CertificateDataGenerator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataGenerator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataGenerator.extractBIN(legalEntitySubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate legalCert = generateUserCert(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), legalEntitySubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, legalCert);
        certificateStorage.getLegalKeys().put(alias, keyPair);
        certificateStorage.getLegalCertificates().put(alias, data);
        return Map.entry(alias, data);
    }

    public Map.Entry<String, CertificateResult> generateCACertificate(String alias) throws Exception {
        if (alias == null || alias.trim().isEmpty()) {
            alias = "ca-" + UUID.randomUUID().toString().substring(0, 8);
        }
        if (certificateStorage.getCaCertificates().containsKey(alias)) {
            throw new IllegalArgumentException("CA alias already exists: " + alias);
        }
        CertificateResult result = generateCACertificate();
        certificateStorage.getCaCertificates().put(alias, result);
        return Map.entry(alias, result);
    }

    public boolean validateXmlSignature(String xml) throws Exception {
        // Use first available CA for validation (default is "default")
        CertificateResult defaultCa = certificateStorage.getCaCertificates().values().iterator().next();
        XmlValidator validator = new XmlValidator(defaultCa.getCertificate());
        return validator.validateXmlSignature(xml);
    }

    private X509Certificate getCertificate(String alias) {
        if (certificateStorage.getUserCertificates().containsKey(alias)) {
            return certificateStorage.getUserCertificates().get(alias).getCertificate();
        }
        if (certificateStorage.getLegalCertificates().containsKey(alias)) {
            return certificateStorage.getLegalCertificates().get(alias).getCertificate();
        }
        if (certificateStorage.getCaCertificates().containsKey(alias)) {
            return certificateStorage.getCaCertificates().get(alias).getCertificate();
        }
        // For backward compatibility
        if ("user".equals(alias) && !certificateStorage.getUserCertificates().isEmpty()) {
            return certificateStorage.getUserCertificates().values().iterator().next().getCertificate();
        }
        if ("legal".equals(alias) && !certificateStorage.getLegalCertificates().isEmpty()) {
            return certificateStorage.getLegalCertificates().values().iterator().next().getCertificate();
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    private PrivateKey getPrivateKey(String alias) {
        if (certificateStorage.getUserKeys().containsKey(alias)) {
            return certificateStorage.getUserKeys().get(alias).getPrivate();
        }
        if (certificateStorage.getLegalKeys().containsKey(alias)) {
            return certificateStorage.getLegalKeys().get(alias).getPrivate();
        }
        // For backward compatibility
        if ("user".equals(alias) && !certificateStorage.getUserKeys().isEmpty()) {
            return certificateStorage.getUserKeys().values().iterator().next().getPrivate();
        }
        if ("legal".equals(alias) && !certificateStorage.getLegalKeys().isEmpty()) {
            return certificateStorage.getLegalKeys().values().iterator().next().getPrivate();
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getKeyFactoryType(), provider.getName());
        kpg.initialize(config.getKeySize());
        return kpg.generateKeyPair();
    }

    @SneakyThrows
    public CertificateResult generateCACertificate() {
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate rootCert = generateRootCA(caKeyPair);
        return new CertificateResult(caKeyPair, rootCert);
    }

    private X509Certificate generateRootCA(KeyPair keyPair) throws Exception {
        KalkanProxy tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        KalkanAdapter.setSerialNumber(tbsGen, serNum);
        KalkanAdapter.setSignature(tbsGen, config.getSignatureAlgorithm());
        String ROOT_SUBJECT_DN = "C=KZ, CN=НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2025";
        KalkanAdapter.setIssuer(tbsGen, ROOT_SUBJECT_DN);
        KalkanAdapter.setSubject(tbsGen, ROOT_SUBJECT_DN);
        KalkanAdapter.setSubjectPublicKeyInfo(tbsGen, keyPair.getPublic());

        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getCaValidityYears());
        Date nextDate = cal.getTime();
        KalkanAdapter.setStartDate(tbsGen, nowDate);
        KalkanAdapter.setEndDate(tbsGen, nextDate);

        KalkanProxy extGen = KalkanAdapter.createX509ExtensionsGenerator();
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.BasicConstraints, true, true);
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.keyCertSign | KalkanConstants.KeyUsage.cRLSign);
        KalkanProxy extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult);

        KalkanProxy tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(keyPair.getPrivate());
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        KalkanProxy certResult = KalkanAdapter.generateCertificate(certGen, tbsResult, signature);
        return certResult.genericValue();
    }

    private X509Certificate generateUserCert(PublicKey userPublicKey, PrivateKey caPrivateKey,
                                             X509Certificate caCert, String subjectDN, String email,
                                             String iin, String bin) throws Exception {
        KalkanProxy tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        KalkanAdapter.setSerialNumber(tbsGen, serNum);
        KalkanAdapter.setSignature(tbsGen, config.getSignatureAlgorithm());
        KalkanAdapter.setIssuer(tbsGen, caCert.getSubjectDN().getName());
        KalkanAdapter.setSubject(tbsGen, subjectDN);
        KalkanAdapter.setSubjectPublicKeyInfo(tbsGen, userPublicKey);

        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getUserValidityYears());
        Date nextDate = cal.getTime();
        KalkanAdapter.setStartDate(tbsGen, nowDate);
        KalkanAdapter.setEndDate(tbsGen, nextDate);

        KalkanProxy extGen = KalkanAdapter.createX509ExtensionsGenerator();
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.BasicConstraints, true, false);
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.digitalSignature | KalkanConstants.KeyUsage.keyEncipherment);

        KalkanAdapter.addExtendedKeyUsageEmailProtection(extGen);

        KalkanProxy sanVector = KalkanAdapter.createASN1EncodableVector();
        KalkanAdapter.addGeneralNameEmail(sanVector, email);
        KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.IIN_OID, iin);
        if (bin != null) {
            KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.BIN_OID, bin);
        }
        KalkanAdapter.addSubjectAlternativeName(extGen, sanVector);

        KalkanProxy extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult);

        KalkanProxy tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(caPrivateKey);
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        KalkanProxy certResult = KalkanAdapter.generateCertificate(certGen, tbsResult, signature);
        return certResult.genericValue();
    }

    private void loadOrGenerateCACertificates() throws Exception {
        Map<String, CertificateResult> loadedCAs = loadCACertificates();
        if (loadedCAs.isEmpty()) {
            // Generate default CA if no CAs are found
            CertificateResult ca = generateCACertificate();
            certificateStorage.getCaCertificates().put(DEFAULT_CA_ALIAS, ca);
        } else {
            // Add loaded CAs
            certificateStorage.getCaCertificates().putAll(loadedCAs);
            // Ensure there's always a default CA
            if (!certificateStorage.getCaCertificates().containsKey(DEFAULT_CA_ALIAS)) {
                CertificateResult ca = generateCACertificate();
                certificateStorage.getCaCertificates().put(DEFAULT_CA_ALIAS, ca);
            }
        }
    }

    private void loadOrGenerateUserCertificates() throws Exception {
        // For each CA, try to load or generate user certificates
        for (String caAlias : certificateStorage.getCaCertificates().keySet()) {
            Map<String, CertificateData> loadedUsers = loadUserCertificates(caAlias);
            if (loadedUsers.isEmpty()) {
                generateUserCertificate(caAlias);
            } else {
                certificateStorage.getUserCertificates().putAll(loadedUsers);
            }
        }
    }

    private void loadOrGenerateLegalCertificates() throws Exception {
        // For each CA, try to load or generate legal certificates
        for (String caAlias : certificateStorage.getCaCertificates().keySet()) {
            Map<String, CertificateData> loadedLegal = loadLegalCertificates(caAlias);
            if (loadedLegal.isEmpty()) {
                generateLegalEntityCertificate(caAlias);
            } else {
                certificateStorage.getLegalCertificates().putAll(loadedLegal);
            }
        }
    }

    private Map<String, CertificateResult> loadCACertificates() throws Exception {
        Map<String, CertificateResult> loadedCAs = new HashMap<>();
        Path certsDir = Paths.get(config.getCertsPath());

        if (!Files.exists(certsDir)) {
            return loadedCAs;
        }

        // Load all ca*.crt files as separate CAs
        try (Stream<Path> paths = Files.walk(certsDir, 1)) {
            paths.filter(path -> {
                String filename = path.getFileName().toString();
                return filename.startsWith("ca") && filename.endsWith(".crt") && Files.isRegularFile(path);
            }).forEach(caCertPath -> {
                try {
                    String filename = caCertPath.getFileName().toString();
                    String alias = filename.substring(0, filename.lastIndexOf('.')); // e.g., "ca2" from "ca2.crt"

                    // Try to load corresponding private key
                    Path caKeyPath = Paths.get(config.getCertsPath(), alias + ".pem");
                    CertificateResult result = loadCACertificateFromFiles(caCertPath, caKeyPath);
                    if (result != null) {
                        loadedCAs.put(alias, result);
                    }
                } catch (Exception e) {
                    log.error("CERT_ERROR: ", e);
                }
            });
        }

        return loadedCAs;
    }

    private CertificateResult loadCACertificateFromFiles(Path caCertPath, Path caKeyPath) throws Exception {
        if (!Files.exists(caCertPath)) {
            return null;
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate caCert;
        try (var is = Files.newInputStream(caCertPath)) {
            caCert = (X509Certificate) certFactory.generateCertificate(is);
        }

        // Try to load CA private key
        PrivateKey caPrivateKey = null;
        if (Files.exists(caKeyPath)) {
            String keyText = Files.readString(caKeyPath);
            // Remove PEM headers and decode
            keyText = keyText.replaceAll("-----[A-Z ]*-----", "").replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(keyText);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            // Look at https://github.com/pkigovkz/java-jwt/blob/master/lib/src/test/java/com/auth0/jwt/algorithms/RSAAlgorithmTest.java#L42
            KeyFactory keyFactory = KeyFactory.getInstance(config.getKeyFactoryType(), provider.getName());
            caPrivateKey = keyFactory.generatePrivate(keySpec);
        }

        if (caPrivateKey == null) {
            // Generate a new key pair if private key is missing
            KeyPair keyPair = generateKeyPair();
            return new CertificateResult(keyPair, caCert);
        } else {
            // Create CertificateResult with loaded key
            KeyPair keyPair = new KeyPair(caCert.getPublicKey(), caPrivateKey);
            return new CertificateResult(keyPair, caCert);
        }
    }

    private Map<String, CertificateData> loadUserCertificates(String caAlias) {
        Map<String, CertificateData> loadedCerts = new HashMap<>();
        try {
            // Try to load from ca-specific keystore first, then fallback to generic user.p12
            Path p12Path = getCertificateFilePath(caAlias, "user");

            if (!Files.exists(p12Path)) {
                // Fallback to generic user.p12 for default CA only
                if (DEFAULT_CA_ALIAS.equals(caAlias)) {
                    p12Path = Paths.get(config.getCertsPath(), "user.p12");
                }
                if (!Files.exists(p12Path)) {
                    return loadedCerts;
                }
            }

            // Load from PKCS12 keystore
            X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                    p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
            PrivateKey privateKey = KeyStoreManager.loadPrivateKeyFromPKCS12(
                    p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");

            // Extract metadata from certificate
            CertificateMetadata metadata = extractCertificateMetadata(cert);
            CertificateData data = new CertificateData(
                    metadata.email, metadata.iin, metadata.bin, caAlias, cert);

            String alias = "user-" + UUID.randomUUID().toString().substring(0, 8);
            certificateStorage.getUserKeys().put(alias, new KeyPair(cert.getPublicKey(), privateKey));
            loadedCerts.put(alias, data);

        } catch (Exception e) {
            log.error("CERT_ERROR: ", e);
        }
        return loadedCerts;
    }

    private Map<String, CertificateData> loadLegalCertificates(String caAlias) {
        Map<String, CertificateData> loadedCerts = new HashMap<>();
        try {
            // Try to load from ca-specific keystore first, then fallback to generic legal.p12
            Path p12Path = getCertificateFilePath(caAlias, "legal");

            if (!Files.exists(p12Path)) {
                // Fallback to generic legal.p12 for default CA only
                if (DEFAULT_CA_ALIAS.equals(caAlias)) {
                    p12Path = Paths.get(config.getCertsPath(), "legal.p12");
                }
                if (!Files.exists(p12Path)) {
                    return loadedCerts;
                }
            }

            // Load from PKCS12 keystore
            X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                    p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
            PrivateKey privateKey = KeyStoreManager.loadPrivateKeyFromPKCS12(
                    p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");

            // Extract metadata from certificate
            CertificateMetadata metadata = extractCertificateMetadata(cert);
            CertificateData data = new CertificateData(
                    metadata.email, metadata.iin, metadata.bin, caAlias, cert);

            String alias = "legal-" + UUID.randomUUID().toString().substring(0, 8);
            certificateStorage.getLegalKeys().put(alias, new KeyPair(cert.getPublicKey(), privateKey));
            loadedCerts.put(alias, data);

        } catch (Exception e) {
            log.error("CERT_ERROR: ", e);
        }
        return loadedCerts;
    }

    private Path getCertificateFilePath(String caAlias, String certType) {
        // For default CA, use generic naming (user.p12, legal.p12)
        if (DEFAULT_CA_ALIAS.equals(caAlias)) {
            return Paths.get(config.getCertsPath(), certType + ".p12");
        }
        // For other CAs, use ca-specific naming (e.g., user-ca2.p12, legal-ca2.p12)
        return Paths.get(config.getCertsPath(), certType + "-" + caAlias + ".p12");
    }

    private CertificateMetadata extractCertificateMetadata(X509Certificate cert) {
        // Use CertificateReader for consistent metadata extraction
        CertificateReader reader = new CertificateReader(config);
        String email = reader.extractEmail(cert);
        String iin = reader.extractIIN(cert);
        String bin = reader.extractBIN(cert);

        return new CertificateMetadata(email, iin, bin);
    }

    private void loadFilesystemCertificates() throws Exception {
        CertificateReader reader = new CertificateReader(config);
        List<CertificateReader.CertificateInfo> certificates = reader.readAllCertificates();
        certificateStorage.getFilesystemCertificates().addAll(certificates);
        log.info("Loaded {} certificates from filesystem", certificates.size());
    }

    public List<CertificateReader.CertificateInfo> getFilesystemCertificates() {
        return new ArrayList<>(certificateStorage.getFilesystemCertificates());
    }

    @Data
    @RequiredArgsConstructor
    private static class CertificateMetadata {
        private final String email;
        private final String iin;
        private final String bin;
    }

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

    @Value
    public static class CertificateStorage {

        Map<String, CertificateResult> caCertificates = new ConcurrentHashMap<>();
        Map<String, KeyPair> userKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> userCertificates = new ConcurrentHashMap<>();
        Map<String, KeyPair> legalKeys = new ConcurrentHashMap<>();
        Map<String, CertificateData> legalCertificates = new ConcurrentHashMap<>();
        Queue<CertificateReader.CertificateInfo> filesystemCertificates = new ConcurrentLinkedQueue<>();

    }

}
