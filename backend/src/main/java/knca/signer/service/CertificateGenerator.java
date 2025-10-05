package knca.signer.service;


import knca.signer.config.ApplicationConfig;
import knca.signer.kalkan.KalkanAdapter;
import knca.signer.kalkan.KalkanConstants;
import knca.signer.kalkan.KalkanProxy;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static knca.signer.kalkan.KalkanConstants.ROOT_SUBJECT_DN;

/**
 * Instance-based certificate generator that uses dependency injection.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateGenerator {

    private final java.security.Provider provider;
    private final ApplicationConfig.CertificateConfig config;


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
        log.info("Generating Root CA...");
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate rootCert = generateRootCA(caKeyPair);

        // Save CA certificate
        saveCertificate(rootCert, config.getCertsPath() + "ca.crt");
        saveCertificate(rootCert, config.getCertsPath() + "ca.pem");

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

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getSignatureAlgorithm(), provider.getName());
        kpg.initialize(config.getKeySize());
        return kpg.generateKeyPair();
    }

    private X509Certificate generateRootCA(KeyPair keyPair) throws Exception {
        KalkanProxy tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        // Set certificate fields
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        KalkanAdapter.setSerialNumber(tbsGen, serNum);
        KalkanAdapter.setSignature(tbsGen, config.getSignatureAlgorithm());
        KalkanAdapter.setIssuer(tbsGen, ROOT_SUBJECT_DN);
        KalkanAdapter.setSubject(tbsGen, ROOT_SUBJECT_DN);
        KalkanAdapter.setSubjectPublicKeyInfo(tbsGen, keyPair.getPublic());

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getCaValidityYears());
        Date nextDate = cal.getTime();
        KalkanAdapter.setStartDate(tbsGen, nowDate);
        KalkanAdapter.setEndDate(tbsGen, nextDate);

        // Extensions
        KalkanProxy extGen = KalkanAdapter.createX509ExtensionsGenerator();
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.BasicConstraints, true, true);
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.keyCertSign | KalkanConstants.KeyUsage.cRLSign);
        var extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult.getResult());

        // Generate TBS certificate
        var tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(keyPair.getPrivate());
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult.getResult());
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        var certResult = KalkanAdapter.generateCertificate(certGen, tbsResult.getResult(), signature);
        return (X509Certificate) certResult.getResult();
    }

    private X509Certificate generateUserCertificate(PublicKey userPublicKey, PrivateKey caPrivateKey,
                                                    X509Certificate caCert, String subjectDN, String email,
                                                    String iin, String bin) throws Exception {
        KalkanProxy tbsGen = KalkanAdapter.createV3TBSCertificateGenerator();

        // Set certificate fields
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

        // Validity period
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.YEAR, config.getUserValidityYears());
        Date nextDate = cal.getTime();
        KalkanAdapter.setStartDate(tbsGen, nowDate);
        KalkanAdapter.setEndDate(tbsGen, nextDate);

        // Extensions
        KalkanProxy extGen = KalkanAdapter.createX509ExtensionsGenerator();
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.BasicConstraints, true, false);
        KalkanAdapter.addExtension(extGen, KalkanConstants.X509Extensions.KeyUsage, true, KalkanConstants.KeyUsage.digitalSignature | KalkanConstants.KeyUsage.keyEncipherment);

        // Extended Key Usage
        KalkanAdapter.addExtendedKeyUsageEmailProtection(extGen);

        // Subject Alternative Name with IIN and BIN
        KalkanProxy sanVector = KalkanAdapter.createASN1EncodableVector();
        KalkanAdapter.addGeneralNameEmail(sanVector, email);
        KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.IIN_OID, iin);
        if (bin != null) {
            KalkanAdapter.addGeneralNameOtherName(sanVector, CertificateDataGenerator.BIN_OID, bin);
        }
        KalkanAdapter.addSubjectAlternativeName(extGen, sanVector);

        var extResult = KalkanAdapter.generateExtensions(extGen);
        KalkanAdapter.setExtensions(tbsGen, extResult.getResult());

        // Generate TBS certificate
        var tbsResult = KalkanAdapter.generateTBSCertificate(tbsGen);

        // Sign the certificate
        Signature sig = Signature.getInstance(config.getSignatureAlgorithm(), provider.getName());
        sig.initSign(caPrivateKey);
        byte[] derEncoded = KalkanAdapter.getDEREncoded(tbsResult.getResult());
        sig.update(derEncoded);
        byte[] signature = sig.sign();

        KalkanProxy certGen = KalkanAdapter.createX509V3CertificateGenerator();
        KalkanAdapter.setSignatureAlgorithm(certGen, config.getSignatureAlgorithm());

        var certResult = KalkanAdapter.generateCertificate(certGen, tbsResult.getResult(), signature);
        return (X509Certificate) certResult.getResult();
    }

    private void saveCertificate(X509Certificate cert, String filename) throws Exception {
        StringWriter stringWriter = new StringWriter();
        KalkanProxy pemWriter = KalkanAdapter.createPEMWriter(stringWriter);
        KalkanAdapter.writeObject(pemWriter, cert);
        KalkanAdapter.flush(pemWriter);
        String pem = stringWriter.toString();
        Path path = Paths.get(filename);
        Files.createDirectories(path.getParent());
        Files.write(path, pem.getBytes(), StandardOpenOption.CREATE);
    }

    /**
     * Simple data class to hold certificate generation results.
     */
    @Data
    @RequiredArgsConstructor
    public static class CertificateResult {

        private final KeyPair keyPair;
        private final X509Certificate certificate;

    }
}
