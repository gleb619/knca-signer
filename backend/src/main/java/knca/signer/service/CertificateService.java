package knca.signer.service;

import knca.signer.config.ApplicationConfig;
import knca.signer.security.KalkanAdapter;
import knca.signer.security.KalkanConstants;
import knca.signer.security.KalkanProxy;
import knca.signer.security.KalkanProxy.ProxyResult;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

@RequiredArgsConstructor
public class CertificateService {

    public static final String DEFAULT_CA_ALIAS = "default";

    private final java.security.Provider provider;
    private final ApplicationConfig.CertificateConfig config;

    private final Map<String, CertificateResult> caCertificates = new HashMap<>();
    private final Map<String, KeyPair> userKeys = new HashMap<>();
    private final Map<String, CertificateData> userCertificates = new HashMap<>();
    private final Map<String, KeyPair> legalKeys = new HashMap<>();
    private final Map<String, CertificateData> legalCertificates = new HashMap<>();

    public CertificateService init() {
        try {
            // Only generate default certificates if no certificates exist
            //TODO: load certificates from folder in `config`
            if (caCertificates.isEmpty() && userCertificates.isEmpty() && legalCertificates.isEmpty()) {
                // Generate default CA in memory
                CertificateResult ca = generateCACertificate();
                caCertificates.put(DEFAULT_CA_ALIAS, ca);

                // Generate user certificate
                generateUserCertificate(DEFAULT_CA_ALIAS);

                // Generate legal certificate
                generateLegalEntityCertificate(DEFAULT_CA_ALIAS);
            }
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
        caCertificates.forEach((alias, result) ->
                certs.put("ca-" + alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        // Add all user certificates
        userCertificates.forEach((alias, data) -> certs.put("user-" + alias, data));
        // Add all legal certificates
        legalCertificates.forEach((alias, data) -> certs.put("legal-" + alias, data));
        return certs;
    }

    public Map<String, CertificateData> getCACertificates() {
        Map<String, CertificateData> cas = new HashMap<>();
        caCertificates.forEach((alias, result) ->
                cas.put(alias, new CertificateData(null, null, null, alias, result.getCertificate())));
        return cas;
    }

    public Map<String, CertificateData> getUserCertificates() {
        return new HashMap<>(userCertificates);
    }

    public Map<String, CertificateData> getLegalCertificates() {
        return new HashMap<>(legalCertificates);
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateUserCertificate(String caId) {
        CertificateResult caResult = caCertificates.get(caId);
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
        userKeys.put(alias, keyPair);
        userCertificates.put(alias, data);
        return Map.entry(alias, data);
    }

    @SneakyThrows
    public Map.Entry<String, CertificateData> generateLegalEntityCertificate(String caId) {
        CertificateResult caResult = caCertificates.get(caId);
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
        legalKeys.put(alias, keyPair);
        legalCertificates.put(alias, data);
        return Map.entry(alias, data);
    }

    public Map.Entry<String, CertificateResult> generateCACertificate(String alias) throws Exception {
        if (alias == null || alias.trim().isEmpty()) {
            alias = "ca-" + UUID.randomUUID().toString().substring(0, 8);
        }
        if (caCertificates.containsKey(alias)) {
            throw new IllegalArgumentException("CA alias already exists: " + alias);
        }
        CertificateResult result = generateCACertificate();
        caCertificates.put(alias, result);
        return Map.entry(alias, result);
    }

    public boolean validateXmlSignature(String xml) throws Exception {
        // Use first available CA for validation (default is "default")
        CertificateResult defaultCa = caCertificates.values().iterator().next();
        XmlValidator validator = new XmlValidator(provider, defaultCa.getCertificate());
        return validator.validateXmlSignature(xml);
    }

    private X509Certificate getCertificate(String alias) {
        if (userCertificates.containsKey(alias)) {
            return userCertificates.get(alias).getCertificate();
        }
        if (legalCertificates.containsKey(alias)) {
            return legalCertificates.get(alias).getCertificate();
        }
        if (caCertificates.containsKey(alias)) {
            return caCertificates.get(alias).getCertificate();
        }
        // For backward compatibility
        if ("user".equals(alias) && !userCertificates.isEmpty()) {
            return userCertificates.values().iterator().next().getCertificate();
        }
        if ("legal".equals(alias) && !legalCertificates.isEmpty()) {
            return legalCertificates.values().iterator().next().getCertificate();
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    private PrivateKey getPrivateKey(String alias) {
        if (userKeys.containsKey(alias)) {
            return userKeys.get(alias).getPrivate();
        }
        if (legalKeys.containsKey(alias)) {
            return legalKeys.get(alias).getPrivate();
        }
        // For backward compatibility
        if ("user".equals(alias) && !userKeys.isEmpty()) {
            return userKeys.values().iterator().next().getPrivate();
        }
        if ("legal".equals(alias) && !legalKeys.isEmpty()) {
            return legalKeys.values().iterator().next().getPrivate();
        }
        throw new IllegalArgumentException("Unknown certificate alias: " + alias);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getSignatureAlgorithm(), provider.getName());
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
        ProxyResult extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult);

        ProxyResult tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(keyPair.getPrivate());
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        ProxyResult certResult = KalkanAdapter.generateCertificate(certGen, tbsResult, signature);
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

        ProxyResult extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult);

        ProxyResult tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(caPrivateKey);
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult);
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        ProxyResult certResult = KalkanAdapter.generateCertificate(certGen, tbsResult, signature);
        return certResult.genericValue();
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

}
