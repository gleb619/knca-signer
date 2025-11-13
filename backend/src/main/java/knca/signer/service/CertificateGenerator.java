package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.api.*;
import knca.signer.service.CertificateService.CertificateData;
import knca.signer.service.CertificateService.CertificateResult;
import lombok.Data;
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



/**
 * Instance-based certificate generator that uses dependency injection.
 * Manages certificate generation and loading operations.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateGenerator {

    private static final String DEFAULT_CA_ALIAS = "default";

    private final Provider provider;
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

        // Always save CA certificate files with ca- prefix for consistency
        String caPrefix = "ca-" + alias;
        saveCertificate(rootCert, "%s%s.crt".formatted(config.getCertsPath(), caPrefix));
        saveCertificate(rootCert, "%s%s.pem".formatted(config.getCertsPath(), caPrefix));

        // Save CA private key in PKCS8 format
        savePrivateKey(caKeyPair.getPrivate(), "%s%s.key".formatted(config.getCertsPath(), caPrefix));

        return new CertificateResult(caKeyPair, rootCert);
    }

    /**
     * Generate user certificate.
     */
    public void generateUserCertificate(KeyPair caKeyPair, X509Certificate rootCert) throws Exception {
        log.info("\nGenerating User Certificate...");

        // Generate user info
        String userSubjectDN = CertificateDataPopulator.populateIndividualSubjectDN();
        String email = CertificateDataPopulator.extractEmail(userSubjectDN);
        String iin = CertificateDataPopulator.extractIIN(userSubjectDN);
        String bin = CertificateDataPopulator.extractBIN(userSubjectDN);

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
        saveCertificate(userCert, "%suser.crt".formatted(config.getCertsPath()));
        saveCertificate(userCert, "%suser.pem".formatted(config.getCertsPath()));

        // Save user private key in PKCS8 format
        savePrivateKey(userKeyPair.getPrivate(), "%suser.key".formatted(config.getCertsPath()));

        // Create keystores
        KeyStoreManager.createPKCS12Keystore(userKeyPair.getPrivate(), userCert, rootCert,
                config.getCertsPath() + "user.p12", config.getKeystorePassword(),
                provider.getName());
        KeyStoreManager.createJKSKeystore(userKeyPair.getPrivate(), userCert, rootCert,
                config.getCertsPath() + "user.jks", config.getKeystorePassword()
        );
    }

    /**
     * Generate legal entity certificate.
     */
    public void generateLegalEntityCertificate(KeyPair caKeyPair, X509Certificate rootCert) throws Exception {
        log.info("\nGenerating Legal Entity Certificate...");

        // Generate legal entity info using shared company and BIN
        var entry = getOrGenerateSharedLegalEntityInfo(DEFAULT_CA_ALIAS);
        String legalEntitySubjectDN = CertificateDataPopulator.populateLegalEntitySubjectDN(entry.getKey(), entry.getValue());
        String email = CertificateDataPopulator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataPopulator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataPopulator.extractBIN(legalEntitySubjectDN);

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
                config.getCertsPath() + "legal.jks", config.getKeystorePassword()
        );
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
    }

    /**
     * Generate a new user certificate.
     */
    @SneakyThrows
    public Map.Entry<String, CertificateData> generateUserCertificate(String caId) {
        CertificateResult caResult = registry.getCACertificate(caId).orElseThrow(() ->
                new IllegalArgumentException("Unknown CA: " + caId));

        String alias = "user-%s-%s".formatted(caId, UUID.randomUUID().toString().substring(0, 8));
        String userSubjectDN = CertificateDataPopulator.populateIndividualSubjectDN();
        String email = CertificateDataPopulator.extractEmail(userSubjectDN);
        String iin = CertificateDataPopulator.extractIIN(userSubjectDN);
        String bin = CertificateDataPopulator.extractBIN(userSubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate userCert = generateUserCertificate(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), userSubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, userCert);
        registry.storeUserCertificate(alias, data, keyPair);
        if ("file".equals(config.getStorageMode())) {
            saveCertificateKeyStore(userCert, keyPair.getPrivate(), caResult.getCertificate(), alias);
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

        String alias = "legal-%s-%s".formatted(caId, UUID.randomUUID().toString().substring(0, 8));
        var entry = getOrGenerateSharedLegalEntityInfo(caId);
        String legalEntitySubjectDN = CertificateDataPopulator.populateLegalEntitySubjectDN(entry.getKey(), entry.getValue());
        String email = CertificateDataPopulator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataPopulator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataPopulator.extractBIN(legalEntitySubjectDN);

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

        String alias = "legal-%s-%s".formatted(caId, UUID.randomUUID().toString().substring(0, 8));
        var entry = getOrGenerateSharedLegalEntityInfo(caId);
        String legalEntitySubjectDN = CertificateDataPopulator.populateLegalEntitySubjectDN(entry.getKey(), entry.getValue());
        String email = CertificateDataPopulator.extractEmail(legalEntitySubjectDN);
        String iin = CertificateDataPopulator.extractIIN(legalEntitySubjectDN);
        String bin = CertificateDataPopulator.extractBIN(legalEntitySubjectDN);

        KeyPair keyPair = generateKeyPair();
        X509Certificate legalCert = generateUserCertificate(keyPair.getPublic(), caResult.getKeyPair().getPrivate(),
                caResult.getCertificate(), legalEntitySubjectDN, email, iin, bin);
        CertificateData data = new CertificateData(email, iin, bin, caId, legalCert);
        registry.storeLegalCertificate(alias, data, keyPair);
        if ("file".equals(config.getStorageMode())) {
            saveCertificateKeyStore(legalCert, keyPair.getPrivate(), caResult.getCertificate(), alias);
        }
        return Map.entry(alias, data);
    }

    /**
     * Generate a new CA certificate with uniqueness check.
     */
    @SneakyThrows
    @Deprecated(forRemoval = true)
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
    @Deprecated(forRemoval = true)
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
                    String alias;
                    String keyPrefix;
                    if (filename.startsWith("ca-")) {
                        alias = filename.substring(3, filename.lastIndexOf('.')); // e.g., "default" from "ca-default.crt"
                        keyPrefix = "ca-" + alias;
                    } else {
                        // Backward compatibility: "ca.crt" -> alias "ca"
                        alias = filename.substring(0, filename.lastIndexOf('.'));
                        keyPrefix = alias;
                    }

                    // Try to load corresponding private key - prefer .key file, fallback to .pem for backward compatibility
                    Path caKeyPath = Paths.get(config.getCertsPath(), keyPrefix + ".key");
                    if (!Files.exists(caKeyPath)) {
                        // Fallback to old .pem location for backward compatibility
                        caKeyPath = Paths.get(config.getCertsPath(), keyPrefix + ".pem");
                        if (Files.exists(caKeyPath)) {
                            log.warn("CA private key found in deprecated location: {}. Please regenerate certificates to use .key files", caKeyPath);
                        }
                    }
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
            try {
                String keyText = Files.readString(caKeyPath);
                if (keyText.contains("BEGIN PRIVATE KEY")) {
                    // This is a private key file
                    keyText = keyText.replaceAll("-----[A-Z ]*-----", "")
                            .replaceAll("\\s", "")
                            //Somehow, sometimes file contains additional symbols at the end
                            .replaceFirst("---$", "");
                    byte[] keyBytes = Base64.getDecoder().decode(keyText);

                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance(config.getKeyFactoryType(), provider.getName());
                    caPrivateKey = keyFactory.generatePrivate(keySpec);
                } else if (keyText.contains("BEGIN CERTIFICATE")) {
                    // This is actually a certificate file (old format), not a private key
                    log.warn("Key path {} contains certificate instead of private key. Key/cert mismatch detected.", caKeyPath);
                } else {
                    // Try to parse as private key anyway, in case it's a raw key format
                    keyText = keyText.replaceAll("-----[A-Z ]*-----", "").replaceAll("\\s", "");
                    byte[] keyBytes = Base64.getDecoder().decode(keyText);

                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance(config.getKeyFactoryType(), provider.getName());
                    caPrivateKey = keyFactory.generatePrivate(keySpec);
                }
            } catch (Exception e) {
                log.warn("Failed to load private key from {}: {}. Generating new key pair.", caKeyPath, e.getMessage());
            }
        }

        if (caPrivateKey == null) {
            // Private key is missing or invalid, return null to force regeneration
            log.info("No valid private key found for CA certificate {}. Will regenerate CA.", caCertPath);
            return null;
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
            String prefix = "%s-%s-".formatted(type.name().toLowerCase(), caAlias);
            try (Stream<Path> paths = Files.walk(certsDir, 1)) {
                paths.filter(path -> {
                    String name = path.getFileName().toString();
                    return name.startsWith(prefix) && name.endsWith(".p12");
                }).forEach(p12Path -> {
                    try {
                        String filename = p12Path.getFileName().toString();
                        String alias = filename.replace(".p12", "");
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
            // If no CA-specific files, try the generic for backward compatibility (only for default CA)
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

    @Deprecated(forRemoval = true)
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

    private void saveCertificateKeyStore(X509Certificate cert, PrivateKey privateKey, X509Certificate caCert, String baseName) throws Exception {
        saveCertificate(cert, config.getCertsPath() + baseName + ".crt");
        saveCertificate(cert, config.getCertsPath() + baseName + ".pem");
        KeyStoreManager.createPKCS12Keystore(privateKey, cert, caCert, "%s%s.p12".formatted(config.getCertsPath(), baseName), config.getKeystorePassword(), provider.getName());
        KeyStoreManager.createJKSKeystore(privateKey, cert, caCert, "%s%s.jks".formatted(config.getCertsPath(), baseName), config.getKeystorePassword());
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getKeyFactoryType(), provider.getName());
        kpg.initialize(config.getKeySize());
        return kpg.generateKeyPair();
    }

    private X509Certificate generateUserCertificate(PublicKey userPublicKey, PrivateKey caPrivateKey,
                                                    X509Certificate caCert, String subjectDN, String email,
                                                    String iin, String bin) throws Exception {
        TBSCertificateManager tbsManager = KalkanAdapter.createTBSCertificateManager();

        // Set certificate fields
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        tbsManager.setSerialNumber(serNum);
        tbsManager.setSignature(config.getSignatureAlgorithm());
        tbsManager.setIssuer(caCert.getSubjectDN().getName());
        tbsManager.setSubject(subjectDN);
        tbsManager.setSubjectPublicKeyInfo(userPublicKey);

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getUserValidityYears());
        Date nextDate = cal.getTime();
        tbsManager.setStartDate(nowDate);
        tbsManager.setEndDate(nextDate);

        // Extensions
        X509ExtensionsGenerator extGen = KalkanAdapter.createX509ExtensionsGenerator();
        extGen.addExtension(KalkanConstants.X509Extensions.BasicConstraints, true, false);
        extGen.addExtension(KalkanConstants.X509Extensions.KeyUsage, true,
                KalkanConstants.KeyUsage.digitalSignature | KalkanConstants.KeyUsage.keyEncipherment);

        // Extended Key Usage
        //TODO: add alternative KeyUsage
        extGen.addExtendedKeyUsageEmailProtection(KalkanConstants.KeyPurposeId.id_kp_emailProtection);

        // Subject Alternative Name with IIN and BIN
        ASN1EncodableVector sanVector = KalkanAdapter.createASN1EncodableVectorWrapper();
        sanVector.addGeneralNameEmail(email);
        sanVector.addGeneralNameOtherName(CertificateDataPopulator.IIN_OID, iin);
        if (bin != null) {
            sanVector.addGeneralNameOtherName(CertificateDataPopulator.BIN_OID, bin);
        }
        extGen.addSubjectAlternativeName(sanVector.getProxy());

        var extResult = extGen.generate();
        tbsManager.setExtensions(extResult.getResult());

        // Generate TBS certificate
        var tbsResult = tbsManager.generateTBSCertificate();

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(caPrivateKey);
        byte[] derEncoded = tbsManager.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        X509V3CertificateGenerator certGen = KalkanAdapter.createX509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(config.getSignatureAlgorithm());

        return certGen.generate(tbsResult, signature);
    }

    @Data
    @RequiredArgsConstructor
    private static class CertificateMetadata {
        private final String email;
        private final String iin;
        private final String bin;
    }

    private X509Certificate generateRootCA(KeyPair keyPair) throws Exception {
        TBSCertificateManager tbsManager = KalkanAdapter.createTBSCertificateManager();

        // Set certificate fields
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        tbsManager.setSerialNumber(serNum);
        tbsManager.setSignature(config.getSignatureAlgorithm());
        String caSubjectDN = CertificateDataPopulator.populateCASubjectDN();
        tbsManager.setIssuer(caSubjectDN);
        tbsManager.setSubject(caSubjectDN);
        tbsManager.setSubjectPublicKeyInfo(keyPair.getPublic());

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getCaValidityYears());
        Date nextDate = cal.getTime();
        tbsManager.setStartDate(nowDate);
        tbsManager.setEndDate(nextDate);

        // Extensions
        X509ExtensionsGenerator extGen = KalkanAdapter.createX509ExtensionsGenerator();
        extGen.addExtension(KalkanConstants.X509Extensions.BasicConstraints, true, true);
        extGen.addExtension(KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.keyCertSign | KalkanConstants.KeyUsage.cRLSign);
        var extResult = extGen.generate();
        tbsManager.setExtensions(extResult.getResult());

        // Generate TBS certificate
        var tbsResult = tbsManager.generateTBSCertificate();

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(keyPair.getPrivate());
        byte[] derEncoded = tbsManager.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        X509V3CertificateGenerator certGen = KalkanAdapter.createX509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(config.getSignatureAlgorithm());

        return certGen.generate(tbsResult, signature);
    }

    @Data
    @RequiredArgsConstructor
    private static class CertificateDataWithKey {
        private final CertificateData data;
        private final KeyPair keyPair;
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

    /**
     * Get or generate shared legal entity info (company and BIN) for the given CA.
     */
    private Map.Entry<String, String> getOrGenerateSharedLegalEntityInfo(String caAlias) {
        var infoOpt = registry.getLegalCompanyInfo(caAlias);
        if (infoOpt.isPresent()) {
            var info = infoOpt.get();
            return Map.entry(info.company(), info.bin());
        } else {
            String company = CertificateDataPopulator.populateCompany();
            String bin = CertificateDataPopulator.populateBIN();
            registry.setLegalCompanyInfo(caAlias, company, bin);
            return Map.entry(company, bin);
        }
    }

    private void savePrivateKey(PrivateKey privateKey, String filename) throws Exception {
        // Convert to PKCS8 encoded format
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());

        // Create PEM format with proper headers
        String base64Key = Base64.getEncoder().encodeToString(pkcs8KeySpec.getEncoded());
        String pemKey = "-----BEGIN PRIVATE KEY-----\n" +
                base64Key.replaceAll("(.{64})", "$1\n") +
                "\n-----END PRIVATE KEY-----\n";

        Path path = Paths.get(filename);
        Files.createDirectories(path.getParent());
        Files.write(path, pemKey.getBytes(), StandardOpenOption.CREATE);
    }

    private enum CertificateType {
        USER, LEGAL
    }

}
