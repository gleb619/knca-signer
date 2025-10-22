package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.KalkanProxy;
import knca.signer.kalkan.api.PEMWriter;
import knca.signer.kalkan.api.V3TBSCertificateGenerator;
import knca.signer.kalkan.api.X509ExtensionsGenerator;
import knca.signer.kalkan.api.X509V3CertificateGenerator;
import knca.signer.service.CertificateService.CertificateData;
import knca.signer.service.CertificateService.CertificateResult;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Stream;

import static knca.signer.kalkan.KalkanConstants.ROOT_SUBJECT_DN;

/**
 * Instance-based certificate generator that uses dependency injection.
 * Manages certificate generation and loading operations.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateGenerator {

    private static final String DEFAULT_CA_ALIAS = "ca";
    @Deprecated(forRemoval = true)
    private static final String SHARED_LEGAL_COMPANY = "ҚАЗАҚСТАН ЖОЛ СЕРВИСІ";
    @Deprecated(forRemoval = true)
    private static final String SHARED_LEGAL_BIN = "123456789012";

    private final java.security.Provider provider;
    private final ApplicationConfig.CertificateConfig config;
    private final CertificateStorage registry;


    /**
     * Generate all certificates (CA, User, Legal Entity).
     */
    public void generateAllCertificates() throws Exception {
        log.info("Starting certificate generation...");

        // Generate Root CA
        CertificateResult caResult = generateCACertificate();
        KeyPair caKeyPair = caResult.getKeyPair();
        X509Certificate rootCert = caResult.getCertificate();

        // Generate User Certificate
        generateUserCertificate(caKeyPair, rootCert);

        // Generate Legal Entity Certificate
        generateLegalEntityCertificate(caKeyPair, rootCert);

        log.info("""
                        Certificate generation completed successfully!
                        CA: ca.crt, ca.pem
                        User: user.crt, user.pem, user.p12, user.jks (password: {})
                        Legal Entity: legal.crt, legal.pem, legal.p12, legal.jks (password: {})""",
                config.getKeystorePassword(), config.getKeystorePassword());
    }

    /**
     * Generate CA certificate.
     */
    public CertificateResult generateCACertificate() throws Exception {
        return generateCACertificateInternal(DEFAULT_CA_ALIAS);
    }

    /**
     * Generate CA certificate with alias.
     */
    public Map.Entry<String, CertificateResult> generateCACertificate(String alias) throws Exception {
        CertificateResult result = generateCACertificateInternal(alias);
        registry.storeCACertificate(alias, result);
        return Map.entry(alias, result);
    }

    /**
     * Generate CA certificate with alias (internal helper).
     */
    private CertificateResult generateCACertificateInternal(String alias) throws Exception {
        if (alias == null || alias.trim().isEmpty()) {
            alias = DEFAULT_CA_ALIAS;
        }
        log.info("Generating Root CA for alias: {}", alias);
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate rootCert = generateRootCA(caKeyPair);

        // Always save CA certificate files
        saveCertificate(rootCert, config.getCertsPath() + alias + ".crt");
        saveCertificate(rootCert, config.getCertsPath() + alias + ".pem");

        return new CertificateResult(caKeyPair, rootCert);
    }

    /**
     * Generate user certificate.
     */
    public void generateUserCertificate(KeyPair caKeyPair, X509Certificate rootCert) throws Exception {
        log.info("\nGenerating User Certificate...");

        // Generate user info
        String userSubjectDN = CertificateDataGenerator.generateIndividualSubjectDN();
        String email = CertificateDataGenerator.extractEmail(userSubjectDN);
        String iin = CertificateDataGenerator.extractIIN(userSubjectDN);
        String bin = CertificateDataGenerator.extractBIN(userSubjectDN);

        // Print user info
        log.info("""
                        User Info:
                        Subject DN: {}
                        Email: {}
                        IIN: {}
                        BIN: {}""",
                userSubjectDN,
                email,
                iin,
                bin != null ? bin : "");

        // Generate certificate
        KeyPair userKeyPair = generateKeyPair();
        X509Certificate userCert = generateUserCertificate(userKeyPair.getPublic(), caKeyPair.getPrivate(),
                rootCert, userSubjectDN, email, iin, bin);

        // Save user certificate
        saveCertificate(userCert, config.getCertsPath() + "user.crt");
        saveCertificate(userCert, config.getCertsPath() + "user.pem");

        // Create keystores
        KeyStoreManager.createPKCS12Keystore(userKeyPair.getPrivate(), userCert, rootCert,
                config.getCertsPath() + "user.p12", config.getKeystorePassword(),
                provider.getName());
        KeyStoreManager.createJKSKeystore(userKeyPair.getPrivate(), userCert, rootCert,
                config.getCertsPath() + "user.jks", config.getKeystorePassword(),
                provider.getName());
    }

    /**
     * Generate legal entity certificate.
     */
    public void generateLegalEntityCertificate(KeyPair caKeyPair, X509Certificate rootCert) throws Exception {
        log.info("\nGenerating Legal Entity Certificate...");

        // Generate legal entity info
        String legalEntitySubjectDN = CertificateDataGenerator.generateLegalEntitySubjectDN();
        String email = CertificateDataGenerator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataGenerator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataGenerator.extractBIN(legalEntitySubjectDN);

        // Print legal entity info
        log.info("""
                        Legal Entity Info:
                        Subject DN: {}
                        Email: {}
                        IIN: {}
                        BIN: {}""",
                legalEntitySubjectDN,
                email,
                iin,
                bin != null ? bin : ""
        );

        // Generate certificate
        KeyPair legalEntityKeyPair = generateKeyPair();
        X509Certificate legalEntityCert = generateUserCertificate(legalEntityKeyPair.getPublic(),
                caKeyPair.getPrivate(), rootCert,
                legalEntitySubjectDN, email, iin, bin);

        // Save legal entity certificate
        saveCertificate(legalEntityCert, config.getCertsPath() + "legal.crt");
        saveCertificate(legalEntityCert, config.getCertsPath() + "legal.pem");

        // Create keystores
        KeyStoreManager.createPKCS12Keystore(legalEntityKeyPair.getPrivate(), legalEntityCert, rootCert,
                config.getCertsPath() + "legal.p12", config.getKeystorePassword(),
                provider.getName());
        KeyStoreManager.createJKSKeystore(legalEntityKeyPair.getPrivate(), legalEntityCert, rootCert,
                config.getCertsPath() + "legal.jks", config.getKeystorePassword(),
                provider.getName());
    }

    /**
     * Initialize the certificate generation service by loading or generating certificates.
     */
    @SneakyThrows
    public void init() {
        log.info("CertificateGenerator.init() started, mode: {}", config.getStorageMode());
        // Load or generate CA certificates
        loadOrGenerateCACertificates();

        // Load or generate user certificates for each CA
        loadOrGenerateUserCertificates();

        // Load or generate legal certificates for each CA
        loadOrGenerateLegalCertificates();

        // Load filesystem certificates for fast retrieval
        loadFilesystemCertificates();
    }

    /**
     * Generate a new user certificate.
     */
    @SneakyThrows
    public Map.Entry<String, CertificateData> generateUserCertificate(String caId) {
        CertificateResult caResult = registry.getCACertificate(caId).orElseThrow(() ->
                new IllegalArgumentException("Unknown CA: " + caId));

        String alias = "user-" + UUID.randomUUID().toString().substring(0, 8);
        String userSubjectDN = CertificateDataGenerator.generateIndividualSubjectDN();
        String email = CertificateDataGenerator.extractEmail(userSubjectDN);
        String iin = CertificateDataGenerator.extractIIN(userSubjectDN);
        String bin = CertificateDataGenerator.extractBIN(userSubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate userCert = generateUserCertificate(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), userSubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, userCert);
        registry.storeUserCertificate(alias, data, keyPair);
        if ("file".equals(config.getStorageMode())) {
            saveCertificateKeyStore(userCert, keyPair.getPrivate(), caResult.getKeyPair().getPrivate(), caResult.getCertificate(), alias);
        }
        return Map.entry(alias, data);
    }

    /**
     * Generate a new legal entity certificate.
     */
    @SneakyThrows
    public Map.Entry<String, CertificateData> generateLegalEntityCertificate(String caId) {
        CertificateResult caResult = registry.getCACertificate(caId).orElseThrow(() ->
                new IllegalArgumentException("Unknown CA: " + caId));

        String alias = "legal-" + UUID.randomUUID().toString().substring(0, 8);
        String legalEntitySubjectDN = CertificateDataGenerator.generateLegalEntitySubjectDN();
        String email = CertificateDataGenerator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataGenerator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataGenerator.extractBIN(legalEntitySubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate legalCert = generateUserCertificate(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), legalEntitySubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, legalCert);
        registry.storeLegalCertificate(alias, data, keyPair);
        return Map.entry(alias, data);
    }

    /**
     * Generate a new legal entity certificate with shared company name and BIN.
     */
    @SneakyThrows
    public Map.Entry<String, CertificateData> generateLegalEntityCertificateWithShared(String caId) {
        CertificateResult caResult = registry.getCACertificate(caId).orElseThrow(() ->
                new IllegalArgumentException("Unknown CA: " + caId));

        String alias = "legal-" + UUID.randomUUID().toString().substring(0, 8);
        String legalEntitySubjectDN = CertificateDataGenerator.generateLegalEntitySubjectDN(SHARED_LEGAL_COMPANY, SHARED_LEGAL_BIN);
        String email = CertificateDataGenerator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataGenerator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataGenerator.extractBIN(legalEntitySubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate legalCert = generateUserCertificate(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), legalEntitySubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, legalCert);
        registry.storeLegalCertificate(alias, data, keyPair);
        if ("file".equals(config.getStorageMode())) {
            saveCertificateKeyStore(legalCert, keyPair.getPrivate(), caResult.getKeyPair().getPrivate(), caResult.getCertificate(), alias);
        }
        return Map.entry(alias, data);
    }

    /**
     * Generate a new CA certificate with uniqueness check.
     */
    @SneakyThrows
    public Map.Entry<String, CertificateResult> generateAndStoreCACertificate(String alias) {
        if (alias == null || alias.trim().isEmpty()) {
            alias = DEFAULT_CA_ALIAS; // Use default alias if null/empty
        }
        if (registry.hasCACertificate(alias)) {
            throw new IllegalArgumentException("CA alias already exists: " + alias);
        }
        CertificateResult result = generateCACertificateInternal(alias);
        registry.storeCACertificate(alias, result);
        return Map.entry(alias, result);
    }

    @SneakyThrows
    private CertificateResult generateNewCACertificate(String alias) {
        if (alias == null || alias.trim().isEmpty()) {
            alias = DEFAULT_CA_ALIAS;
        }
        log.info("Generating new CA certificate with alias: {}", alias);
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate rootCert = generateRootCA(caKeyPair);

        // Always save CA certificate files
        saveCertificate(rootCert, config.getCertsPath() + alias + ".crt");
        saveCertificate(rootCert, config.getCertsPath() + alias + ".pem");

        return new CertificateResult(caKeyPair, rootCert);
    }

    private void loadOrGenerateCACertificates() throws Exception {
        Map<String, CertificateResult> loadedCAs = loadCACertificates();
        if (loadedCAs.isEmpty()) {
            // Generate default CA if no CAs are found
            CertificateResult ca = generateCACertificateInternal(DEFAULT_CA_ALIAS);
            registry.storeCACertificate(DEFAULT_CA_ALIAS, ca);
        } else {
            // Add loaded CAs
            loadedCAs.forEach(registry::storeCACertificate);
            // Ensure there's always a default CA
            if (!registry.hasCACertificate(DEFAULT_CA_ALIAS)) {
                CertificateResult ca = generateCACertificateInternal(DEFAULT_CA_ALIAS);
                registry.storeCACertificate(DEFAULT_CA_ALIAS, ca);
            }
        }
    }

    private void loadOrGenerateUserCertificates() throws Exception {
        // For each CA, try to load or generate user certificates
        for (String caAlias : registry.getCACertificateAliases()) {
            Map<CertificateDataWithKey, String> loadedUsers = loadUserCertificates(caAlias);
            if (loadedUsers.isEmpty()) {
                for (int i = 0; i < config.getInitialUserCertificates(); i++) {
                    generateUserCertificate(caAlias);
                }
            } else {
                loadedUsers.forEach((dataWithKey, alias) -> registry.addUserCertificate(alias, dataWithKey.getData(), dataWithKey.getKeyPair()));
            }
        }
    }

    private void loadOrGenerateLegalCertificates() throws Exception {
        // For each CA, try to load or generate legal certificates
        for (String caAlias : registry.getCACertificateAliases()) {
            Map<CertificateDataWithKey, String> loadedLegal = loadLegalCertificates(caAlias);
            if (loadedLegal.isEmpty()) {
                for (int i = 0; i < config.getInitialLegalCertificates(); i++) {
                    generateLegalEntityCertificateWithShared(caAlias);
                }
            } else {
                loadedLegal.forEach((dataWithKey, alias) -> registry.addLegalCertificate(alias, dataWithKey.getData(), dataWithKey.getKeyPair()));
            }
        }
    }

    private void loadFilesystemCertificates() throws Exception {
        CertificateReader reader = new CertificateReader(config);
        List<CertificateReader.CertificateInfo> certificates = reader.readAllCertificates();
        registry.clearFilesystemCertificates();
        certificates.forEach(registry::addFilesystemCertificate);
        log.info("Loaded {} certificates from filesystem", certificates.size());
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

    private Map<CertificateDataWithKey, String> loadUserCertificates(String caAlias) {
        // Simplified - delegate to common logic
        return loadCertificates(caAlias, CertificateType.USER);
    }

    private Map<CertificateDataWithKey, String> loadLegalCertificates(String caAlias) {
        // Simplified - delegate to common logic
        return loadCertificates(caAlias, CertificateType.LEGAL);
    }

    private Map<CertificateDataWithKey, String> loadCertificates(String caAlias, CertificateType type) {
        Map<CertificateDataWithKey, String> loadedCerts = new HashMap<>();
        try {
            Path certsDir = Paths.get(config.getCertsPath());
            if (!Files.exists(certsDir)) {
                return loadedCerts;
            }
            String prefix = type.name().toLowerCase() + "-";
            try (Stream<Path> paths = Files.walk(certsDir, 1)) {
                paths.filter(path -> {
                    String name = path.getFileName().toString();
                    return name.startsWith(prefix) && name.endsWith(".p12");
                }).forEach(p12Path -> {
                    try {
                        String alias = p12Path.getFileName().toString().replace(".p12", "");
                        // Load from PKCS12 keystore
                        X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                                p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
                        PrivateKey privateKey = KeyStoreManager.loadPrivateKeyFromPKCS12(
                                p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");

                        CertificateMetadata metadata = extractCertificateMetadata(cert);
                        CertificateData data = new CertificateData(metadata.email, metadata.iin, metadata.bin, caAlias, cert);

                        KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
                        CertificateDataWithKey dataWithKey = new CertificateDataWithKey(data, keyPair);
                        loadedCerts.put(dataWithKey, alias);
                    } catch (Exception e) {
                        log.error("Error loading cert from {}", p12Path, e);
                    }
                });
            }
            // If no prefixed files, try the generic for backward compatibility
            if (DEFAULT_CA_ALIAS.equals(caAlias) && loadedCerts.isEmpty()) {
                Path p12Path = Paths.get(config.getCertsPath(), type.name().toLowerCase() + ".p12");
                if (Files.exists(p12Path)) {
                    try {
                        String alias = type.name().toLowerCase();
                        X509Certificate cert = KeyStoreManager.loadCertificateFromPKCS12(
                                p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");
                        PrivateKey privateKey = KeyStoreManager.loadPrivateKeyFromPKCS12(
                                p12Path.toString(), config.getKeystorePassword(), "user", "KALKAN");

                        CertificateMetadata metadata = extractCertificateMetadata(cert);
                        CertificateData data = new CertificateData(metadata.email, metadata.iin, metadata.bin, caAlias, cert);

                        KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
                        CertificateDataWithKey dataWithKey = new CertificateDataWithKey(data, keyPair);
                        loadedCerts.put(dataWithKey, alias);
                    } catch (Exception e) {
                        log.error("Error loading cert from {}", p12Path, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("CERT_ERROR: ", e);
        }
        return loadedCerts;
    }

    private Path getCertificateFilePath(String caAlias, CertificateType certType) {
        // For default CA, use generic naming (user.p12, legal.p12)
        if (DEFAULT_CA_ALIAS.equals(caAlias)) {
            return Paths.get(config.getCertsPath(), certType.name().toLowerCase() + ".p12");
        }
        // For other CAs, use ca-specific naming (e.g., user-ca2.p12, legal-ca2.p12)
        return Paths.get(config.getCertsPath(), certType.name().toLowerCase() + "-" + caAlias + ".p12");
    }

    private CertificateMetadata extractCertificateMetadata(X509Certificate cert) {
        // Use CertificateReader for consistent metadata extraction
        CertificateReader reader = new CertificateReader(config); // TODO: Need config
        String email = reader.extractEmail(cert);
        String iin = reader.extractIIN(cert);
        String bin = reader.extractBIN(cert);

        return new CertificateMetadata(email, iin, bin);
    }

    private void saveCertificateKeyStore(X509Certificate cert, PrivateKey privateKey, PrivateKey caPrivateKey, X509Certificate caCert, String baseName) throws Exception {
        saveCertificate(cert, config.getCertsPath() + baseName + ".crt");
        saveCertificate(cert, config.getCertsPath() + baseName + ".pem");
        KeyStoreManager.createPKCS12Keystore(privateKey, cert, caCert, config.getCertsPath() + baseName + ".p12", config.getKeystorePassword(), provider.getName());
        KeyStoreManager.createJKSKeystore(privateKey, cert, caCert, config.getCertsPath() + baseName + ".jks", config.getKeystorePassword(), provider.getName());
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getKeyFactoryType(), provider.getName());
        kpg.initialize(config.getKeySize());
        return kpg.generateKeyPair();
    }

    private enum CertificateType {USER, LEGAL}

    @lombok.Data
    @lombok.RequiredArgsConstructor
    private static class CertificateMetadata {
        private final String email;
        private final String iin;
        private final String bin;
    }

    @lombok.Data
    @lombok.RequiredArgsConstructor
    private static class CertificateDataWithKey {
        private final CertificateData data;
        private final KeyPair keyPair;
    }

    private X509Certificate generateRootCA(KeyPair keyPair) throws Exception {
        V3TBSCertificateGenerator tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        // Set certificate fields
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        tbsGen.setSerialNumber(serNum);
        tbsGen.setSignature(config.getSignatureAlgorithm());
        tbsGen.setIssuer(ROOT_SUBJECT_DN);
        tbsGen.setSubject(ROOT_SUBJECT_DN);
        tbsGen.setSubjectPublicKeyInfo(keyPair.getPublic());

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getCaValidityYears());
        Date nextDate = cal.getTime();
        tbsGen.setStartDate(nowDate);
        tbsGen.setEndDate(nextDate);

        // Extensions
        X509ExtensionsGenerator extGen = KalkanAdapter.createX509ExtensionsGenerator();
        extGen.addExtension(KalkanConstants.X509Extensions.BasicConstraints, true, true);
        extGen.addExtension(KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.keyCertSign | KalkanConstants.KeyUsage.cRLSign);
        var extResult = extGen.generate();
        tbsGen.setExtensions(extResult.getResult());

        // Generate TBS certificate
        var tbsResult = tbsGen.generateTBSCertificate();

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(keyPair.getPrivate());
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        X509V3CertificateGenerator certGen = KalkanAdapter.createX509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(config.getSignatureAlgorithm());

        return certGen.generate(tbsResult, signature);
    }

    private X509Certificate generateUserCertificate(PublicKey userPublicKey, PrivateKey caPrivateKey,
                                                    X509Certificate caCert, String subjectDN, String email,
                                                    String iin, String bin) throws Exception {
        V3TBSCertificateGenerator tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        // Set certificate fields
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        tbsGen.setSerialNumber(serNum);
        tbsGen.setSignature(config.getSignatureAlgorithm());
        tbsGen.setIssuer(caCert.getSubjectDN().getName());
        tbsGen.setSubject(subjectDN);
        tbsGen.setSubjectPublicKeyInfo(userPublicKey);

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getUserValidityYears());
        Date nextDate = cal.getTime();
        tbsGen.setStartDate(nowDate);
        tbsGen.setEndDate(nextDate);

        // Extensions
        X509ExtensionsGenerator extGen = KalkanAdapter.createX509ExtensionsGenerator();
        extGen.addExtension(KalkanConstants.X509Extensions.BasicConstraints, true, false);
        extGen.addExtension(KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.digitalSignature | KalkanConstants.KeyUsage.keyEncipherment);

        // Extended Key Usage
        extGen.addExtendedKeyUsageEmailProtection();

        // Subject Alternative Name with IIN and BIN
        KalkanProxy sanVector = KalkanAdapter.createASN1EncodableVector();
        KalkanAdapter.addGeneralNameEmail(sanVector, email);
        KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.IIN_OID, iin);
        if (bin != null) {
            KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.BIN_OID, bin);
        }
        extGen.addSubjectAlternativeName(sanVector);

        var extResult = extGen.generate();
        tbsGen.setExtensions(extResult.getResult());

        // Generate TBS certificate
        var tbsResult = tbsGen.generateTBSCertificate();

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(caPrivateKey);
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        X509V3CertificateGenerator certGen = KalkanAdapter.createX509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(config.getSignatureAlgorithm());

        return certGen.generate(tbsResult, signature);
    }

    private void saveCertificate(X509Certificate cert, String filename) throws Exception {
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = KalkanAdapter.createPEMWriter(stringWriter);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        String pem = stringWriter.toString();
        Path path = Paths.get(filename);
        Files.createDirectories(path.getParent());
        Files.write(path, pem.getBytes(), StandardOpenOption.CREATE);
    }

}
