package knca.signer.service;

import knca.signer.controller.VerifierHandler.XmlValidationRequest;
import knca.signer.util.XmlUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Service for XML signature validation and certificate chain validation.
 * Handles XML signature operations and related validations.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateValidator {

    private final Provider provider;
    private final CertificateStorage registry;

    /**
     * Validate a certificate against a CA certificate.
     */
    public static void validateCertificate(X509Certificate userCert, X509Certificate caCert, Provider provider) throws Exception {
        // Verify certificate signature using provider
        String sigAlgo = userCert.getSigAlgName();
        Signature sig = Signature.getInstance(sigAlgo, provider.getName());
        sig.initVerify(caCert.getPublicKey());
        sig.update(userCert.getTBSCertificate());
        if (!sig.verify(userCert.getSignature())) {
            throw new Exception("Certificate signature validation failed");
        }

        // Check validity
        userCert.checkValidity();

        log.info("Certificate validated successfully against CA");
    }

    /**
     * Validate certificate chain.
     */
    public static void validateCertificateChain(X509Certificate[] chain, X509Certificate caCert, Provider provider) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Certificate chain is empty");
        }

        // Validate each certificate in the chain
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate cert = chain[i];
            X509Certificate issuer = chain[i + 1];
            // Verify certificate signature using provider
            String sigAlgo = cert.getSigAlgName();
            Signature sig = Signature.getInstance(sigAlgo, provider.getName());
            sig.initVerify(issuer.getPublicKey());
            sig.update(cert.getTBSCertificate());
            if (!sig.verify(cert.getSignature())) {
                throw new Exception("Certificate signature validation failed for chain[%d]".formatted(i));
            }
            cert.checkValidity();
        }

        // Validate the root certificate against CA if it's not self-signed
        X509Certificate rootCert = chain[chain.length - 1];
        if (!rootCert.getSubjectDN().equals(rootCert.getIssuerDN())) {
            // Verify root certificate signature
            String sigAlgo = rootCert.getSigAlgName();
            Signature sig = Signature.getInstance(sigAlgo, provider.getName());
            sig.initVerify(caCert.getPublicKey());
            sig.update(rootCert.getTBSCertificate());
            if (!sig.verify(rootCert.getSignature())) {
                throw new Exception("Root certificate signature validation failed");
            }
        }
        rootCert.checkValidity();

        log.info("Certificate chain validated successfully");
    }

    /**
     * Validate XML signature.
     */
    public CertificateService.ValidationResult validateXmlSignature(XmlValidationRequest request) throws Exception {
        List<CertificateService.ValidationDetail> details = new ArrayList<>();
        CertificateService.ValidationResult result = new CertificateService.ValidationResult(true, "validationSuccessBasic", "XML signature validation successful", details);

        CertificateService.CertificateResult defaultCa = registry.getFirstCACertificate().orElseThrow();
        X509Certificate caCertForValidation = parseCaCertificateForKeyValidation(request, defaultCa.getCertificate());

        // Perform signature validation if requested
        if (request.isCheckSignature()) {
            performSignatureValidation(request, result, details);

            // If signature validation failed, return early
            if (!result.isValid()) {
                return result;
            }
        }

        // Perform validation steps based on request flags
        if (request.isCheckKncaProvider()) performKncaProviderCheck(request, result, details);
        if (request.isCheckIinInCert()) performIinCertCheck(request, result, details);
        if (request.isCheckBinInCert()) performBinCertCheck(request, result, details);
        if (request.isCheckCertificateChain())
            performCertChainCheck(request, result, details, defaultCa.getCertificate());
        if (request.isCheckPublicKey()) performPublicKeyCheck(request, provider, result, details);
        if (request.isCheckExtendedKeyUsage()) performExtendedKeyUsageCheck(request, result, details);

        return result;
    }

    private void performSignatureValidation(XmlValidationRequest request,
                                            CertificateService.ValidationResult result,
                                            List<CertificateService.ValidationDetail> details) {
        try {
            boolean signatureValid = XmlUtil.validateXmlSignature(request.getXml());
            if (!signatureValid) {
                result.setValid(false);
                result.setCode("validationErrorSignatureInvalid");
                result.setMessage("XML signature is invalid");
                details.add(CertificateService.ValidationDetail.builder()
                        .key("signature")
                        .type("check")
                        .status("failed")
                        .build());
            } else {
                details.add(CertificateService.ValidationDetail.builder()
                        .key("signature")
                        .type("check")
                        .status("passed")
                        .build());
            }
        } catch (Exception e) {
            log.error("Xml validation failed: ", e);
            result.setValid(false);
            result.setCode("validationErrorGeneral");
            result.setMessage("Validation failed: %s".formatted(e.getMessage()));
            details.add(CertificateService.ValidationDetail.builder()
                    .key("general")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
        }
    }

    private void performKncaProviderCheck(XmlValidationRequest request,
                                          CertificateService.ValidationResult result,
                                          List<CertificateService.ValidationDetail> details) {
        try {
            XmlUtil.checkKncaProvider(request.getXml());
            details.add(CertificateService.ValidationDetail.builder()
                    .key("kalkanProvider")
                    .type("check")
                    .status("passed")
                    .build());
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("kalkanProvider")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorProviderKalkan");
            result.setMessage("Kalkan provider check failed: %s".formatted(e.getMessage()));
        }
    }

    private void performIinCertCheck(XmlValidationRequest request,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            Objects.requireNonNull(request.getExpectedIin(), "The expected value for the IIN was not transmitted");
            String certIin = XmlUtil.extractIinFromCertificate(request.getXml());
            boolean iinMatches;
            if (request.getExpectedIin().startsWith("IIN") && Objects.equals(request.getExpectedIin(), certIin)) {
                iinMatches = true;
            } else if (Objects.nonNull(certIin)) {
                iinMatches = Objects.equals(request.getExpectedIin(), certIin.replaceAll("[^\\d]+", ""));
            } else {
                iinMatches = false;
            }

            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateIin")
                    .type("extraction")
                    .value(certIin)
                    .status(iinMatches ? "passed" : (certIin != null ? "failed" : "not_found"))
                    .build());

            if (!iinMatches && request.getExpectedIin() != null) {
                result.setValid(false);
                result.setCode("validationErrorIinMismatch");
                result.setMessage("Certificate IIN does not match expected value");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateIin")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorIinCertificate");
            result.setMessage("Certificate IIN check failed: " + e.getMessage());
        }
    }

    private void performBinCertCheck(XmlValidationRequest request,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            String certBin = XmlUtil.extractBinFromCertificate(request.getXml());
            boolean binMatches;
            if (request.getExpectedBin().startsWith("BIN") && Objects.equals(request.getExpectedBin(), certBin)) {
                binMatches = true;
            } else if (Objects.nonNull(certBin)) {
                binMatches = Objects.equals(request.getExpectedBin(), certBin.replaceAll("[^\\d]+", ""));
            } else {
                binMatches = false;
            }

            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateBin")
                    .type("extraction")
                    .value(certBin)
                    .status(binMatches ? "passed" : (certBin != null ? "failed" : "not_found"))
                    .build());

            if (!binMatches && request.getExpectedBin() != null) {
                result.setValid(false);
                result.setCode("validationErrorBinMismatch");
                result.setMessage("Certificate BIN does not match expected value");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateBin")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorBinCertificate");
            result.setMessage("Certificate BIN check failed: " + e.getMessage());
        }
    }

    private void performCertChainCheck(XmlValidationRequest request,
                                       CertificateService.ValidationResult result,
                                       List<CertificateService.ValidationDetail> details,
                                       X509Certificate defaultCaCert) {
        try {
            X509Certificate caCertToUse = parseCaCertificateForChainValidation(request, defaultCaCert);

            // Certificate chain validation should be handled directly in the service
            // Extract certificate from XML and validate chain
            Document doc = XmlUtil.parseXmlDocument(request.getXml());
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
            if (nl.getLength() > 0) {
                String certData = nl.item(0).getTextContent();
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                validateCertificateChain(new X509Certificate[]{cert}, caCertToUse, provider);
                details.add(CertificateService.ValidationDetail.builder()
                        .key("certificateChain")
                        .type("check")
                        .status("passed")
                        .build());
            } else {
                details.add(CertificateService.ValidationDetail.builder()
                        .key("certificateChain")
                        .type("check")
                        .status("failed")
                        .build());
                result.setValid(false);
                result.setCode("validationErrorChainInvalid");
                result.setMessage("Certificate chain validation failed - no certificate found");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateChain")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorChainCheck");
            result.setMessage("Certificate chain validation failed: " + e.getMessage());
        }
    }

    private X509Certificate parseCaCertificateForKeyValidation(XmlValidationRequest request, X509Certificate defaultCaCert) throws Exception {
        if (request.getCaPem() != null && !request.getCaPem().trim().isEmpty()) {
            String pemContent = request.getCaPem().trim();
            try {
                // Try to decode as base64 first
                byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
                pemContent = new String(decodedBytes).trim();
            } catch (Exception base64Exception) {
                // If base64 decode fails, treat as plain PEM text
            }

            // Remove PEM headers/footers and clean up
            pemContent = pemContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] certBytes = Base64.getDecoder().decode(pemContent);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate customCa = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            log.info("Using custom CA certificate for key validation");
            return customCa;
        }
        return defaultCaCert;
    }

    private X509Certificate parseCaCertificateForChainValidation(XmlValidationRequest request, X509Certificate defaultCaCert) throws Exception {
        if (request.getCaPem() != null && !request.getCaPem().trim().isEmpty()) {
            String pemContent = request.getCaPem().trim();
            try {
                // Try to decode as base64 first
                byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
                pemContent = new String(decodedBytes).trim();
            } catch (Exception base64Exception) {
                // If base64 decode fails, treat as plain PEM text
            }

            // Remove PEM headers/footers and clean up
            pemContent = pemContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] certBytes = Base64.getDecoder().decode(pemContent);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate customCa = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            log.info("Using custom CA certificate for chain validation");
            return customCa;
        }
        return defaultCaCert;
    }

    private void performPublicKeyCheck(XmlValidationRequest request,
                                       Provider provider,
                                       CertificateService.ValidationResult result,
                                       List<CertificateService.ValidationDetail> details) {
        try {
            boolean publicKeyValid = XmlUtil.validatePublicKey(request.getXml(), request.getPublicKey(), provider);
            details.add(CertificateService.ValidationDetail.builder()
                    .key("publicKey")
                    .type("check")
                    .status(publicKeyValid ? "passed" : "failed")
                    .build());
            if (!publicKeyValid) {
                result.setValid(false);
                result.setCode("validationErrorPublicKey");
                result.setMessage("Public key validation failed - provided key does not match certificate");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("publicKey")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorPublicKey");
            result.setMessage("Public key validation error: " + e.getMessage());
        }
    }

    /**
     * Load CA certificate from file.
     */
    public static X509Certificate loadCACertificate(String caCertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(caCertPath)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private void performExtendedKeyUsageCheck(XmlValidationRequest request,
                                              CertificateService.ValidationResult result,
                                              List<CertificateService.ValidationDetail> details) {
        try {
            boolean extendedKeyUsageValid = XmlUtil.checkExtendedKeyUsage(request.getXml(), request.getExtendedKeyUsageOids());
            details.add(CertificateService.ValidationDetail.builder()
                    .key("extendedKeyUsage")
                    .type("check")
                    .status(extendedKeyUsageValid ? "passed" : "failed")
                    .build());
            if (!extendedKeyUsageValid) {
                result.setValid(false);
                result.setCode("validationErrorEkuInvalid");
                result.setMessage("Extended key usage validation failed - certificate EKU does not match required OIDs");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("extendedKeyUsage")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorEkuCheck");
            result.setMessage("Extended key usage validation error: " + e.getMessage());
        }
    }

}
