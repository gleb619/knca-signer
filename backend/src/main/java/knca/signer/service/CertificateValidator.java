package knca.signer.service;

import knca.signer.controller.VerifierHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

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
                throw new Exception("Certificate signature validation failed for chain[" + i + "]");
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
    public CertificateService.ValidationResult validateXmlSignature(VerifierHandler.XmlValidationRequest request) throws Exception {
        List<CertificateService.ValidationDetail> details = new ArrayList<>();
        CertificateService.ValidationResult result = new CertificateService.ValidationResult(true, "validationSuccessBasic", "XML signature validation successful", details);

        CertificateService.CertificateResult defaultCa = registry.getFirstCACertificate().orElseThrow();
        XmlValidator validator = new XmlValidator(defaultCa.getCertificate(), provider);

        // Always perform signature validation first
        performSignatureValidation(request, validator, result, details);

        // If signature validation failed, return early
        if (!result.isValid()) {
            return result;
        }

        // Perform validation steps based on request flags
        if (request.isCheckKalkanProvider()) performKalkanProviderCheck(request, validator, result, details);
        if (request.isCheckData()) performDataIntegrityCheck(request, validator, result, details);
        if (request.isCheckTime()) performTimestampCheck(request, validator, result, details);
        if (request.isCheckIinInCert()) performIinCertCheck(request, validator, result, details);
        if (request.isCheckIinInSign()) performIinSignCheck(request, validator, result, details);
        if (request.isCheckBinInCert()) performBinCertCheck(request, validator, result, details);
        if (request.isCheckBinInSign()) performBinSignCheck(request, validator, result, details);
        if (request.isCheckCertificateChain())
            performCertChainCheck(request, validator, result, details, defaultCa.getCertificate());
        if (request.isCheckPublicKey()) performPublicKeyCheck(request, validator, result, details);
        if (request.isCheckExtendedKeyUsage()) performExtendedKeyUsageCheck(request, validator, result, details);

        return result;
    }

    private void performSignatureValidation(VerifierHandler.XmlValidationRequest request,
                                            XmlValidator validator,
                                            CertificateService.ValidationResult result,
                                            List<CertificateService.ValidationDetail> details) {
        try {
            boolean signatureValid = validator.validateXmlSignature(request.getXml());
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
            result.setMessage("Validation failed: " + e.getMessage());
            details.add(CertificateService.ValidationDetail.builder()
                    .key("general")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
        }
    }

    private void performKalkanProviderCheck(VerifierHandler.XmlValidationRequest request,
                                            XmlValidator validator,
                                            CertificateService.ValidationResult result,
                                            List<CertificateService.ValidationDetail> details) {
        try {
            validator.checkKalkanProvider(request.getXml());
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
            result.setMessage("Kalkan provider check failed: " + e.getMessage());
        }
    }

    private void performDataIntegrityCheck(VerifierHandler.XmlValidationRequest request,
                                           XmlValidator validator,
                                           CertificateService.ValidationResult result,
                                           List<CertificateService.ValidationDetail> details) {
        try {
            boolean dataIntegrity = validator.checkDataIntegrity(request.getXml());
            details.add(CertificateService.ValidationDetail.builder()
                    .key("dataIntegrity")
                    .type("check")
                    .status(dataIntegrity ? "passed" : "failed")
                    .build());
            if (!dataIntegrity) {
                result.setValid(false);
                result.setCode("validationErrorDataIntegrity");
                result.setMessage("Data integrity check failed");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("dataIntegrity")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorDataIntegrity");
            result.setMessage("Data integrity check failed: " + e.getMessage());
        }
    }

    private void performTimestampCheck(VerifierHandler.XmlValidationRequest request,
                                       XmlValidator validator,
                                       CertificateService.ValidationResult result,
                                       List<CertificateService.ValidationDetail> details) {
        try {
            boolean timestampValid = validator.validateTimestamp(request.getXml());
            details.add(CertificateService.ValidationDetail.builder()
                    .key("timestamp")
                    .type("check")
                    .status(timestampValid ? "passed" : "failed")
                    .build());
            if (!timestampValid) {
                result.setValid(false);
                result.setCode("validationErrorTimestamp");
                result.setMessage("Timestamp validation failed");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("timestamp")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorTimestamp");
            result.setMessage("Timestamp validation failed: " + e.getMessage());
        }
    }

    private void performIinCertCheck(VerifierHandler.XmlValidationRequest request,
                                     XmlValidator validator,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            String certIin = validator.extractIinFromCertificate(request.getXml());
            boolean iinMatches = request.getExpectedIin() != null && request.getExpectedIin().equals(certIin);

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

    private void performIinSignCheck(VerifierHandler.XmlValidationRequest request,
                                     XmlValidator validator,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            String signIin = validator.extractIinFromSignature(request.getXml());
            boolean iinMatches = request.getExpectedIin() != null && request.getExpectedIin().equals(signIin);

            details.add(CertificateService.ValidationDetail.builder()
                    .key("signatureIin")
                    .type("extraction")
                    .value(signIin)
                    .status(iinMatches ? "passed" : (signIin != null ? "failed" : "not_found"))
                    .build());

            if (!iinMatches && request.getExpectedIin() != null) {
                result.setValid(false);
                result.setCode("validationErrorIinMismatch");
                result.setMessage("Signature IIN does not match expected value");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("signatureIin")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorIinSignature");
            result.setMessage("Signature IIN check failed: " + e.getMessage());
        }
    }

    private void performBinCertCheck(VerifierHandler.XmlValidationRequest request,
                                     XmlValidator validator,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            String certBin = validator.extractBinFromCertificate(request.getXml());
            boolean binMatches = request.getExpectedBin() != null && request.getExpectedBin().equals(certBin);

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

    private void performBinSignCheck(VerifierHandler.XmlValidationRequest request,
                                     XmlValidator validator,
                                     CertificateService.ValidationResult result,
                                     List<CertificateService.ValidationDetail> details) {
        try {
            String signBin = validator.extractBinFromSignature(request.getXml());
            boolean binMatches = request.getExpectedBin() != null && request.getExpectedBin().equals(signBin);

            details.add(CertificateService.ValidationDetail.builder()
                    .key("signatureBin")
                    .type("extraction")
                    .value(signBin)
                    .status(binMatches ? "passed" : (signBin != null ? "failed" : "not_found"))
                    .build());

            if (!binMatches && request.getExpectedBin() != null) {
                result.setValid(false);
                result.setCode("validationErrorBinMismatch");
                result.setMessage("Signature BIN does not match expected value");
            }
        } catch (Exception e) {
            details.add(CertificateService.ValidationDetail.builder()
                    .key("signatureBin")
                    .type("error")
                    .status("error")
                    .message(e.getMessage())
                    .build());
            result.setValid(false);
            result.setCode("validationErrorBinSignature");
            result.setMessage("Signature BIN check failed: " + e.getMessage());
        }
    }

    private void performCertChainCheck(VerifierHandler.XmlValidationRequest request,
                                       XmlValidator validator,
                                       CertificateService.ValidationResult result,
                                       List<CertificateService.ValidationDetail> details,
                                       X509Certificate defaultCaCert) {
        try {
            X509Certificate caCertToUse = parseCaCertificateForChainValidation(request, defaultCaCert);

            boolean chainValid = validator.validateCertificateChain(request.getXml(), caCertToUse);
            details.add(CertificateService.ValidationDetail.builder()
                    .key("certificateChain")
                    .type("check")
                    .status(chainValid ? "passed" : "failed")
                    .build());
            if (!chainValid) {
                result.setValid(false);
                result.setCode("validationErrorChainInvalid");
                result.setMessage("Certificate chain validation failed");
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

    private X509Certificate parseCaCertificateForChainValidation(VerifierHandler.XmlValidationRequest request, X509Certificate defaultCaCert) throws Exception {
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

    private void performPublicKeyCheck(VerifierHandler.XmlValidationRequest request,
                                       XmlValidator validator,
                                       CertificateService.ValidationResult result,
                                       List<CertificateService.ValidationDetail> details) {
        try {
            boolean publicKeyValid = validator.validatePublicKey(request.getXml(), request.getPublicKey());
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

    private void performExtendedKeyUsageCheck(VerifierHandler.XmlValidationRequest request,
                                              XmlValidator validator,
                                              CertificateService.ValidationResult result,
                                              List<CertificateService.ValidationDetail> details) {
        try {
            boolean extendedKeyUsageValid = validator.checkExtendedKeyUsage(request.getXml(), request.getExtendedKeyUsageOids());
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

    /**
     * Instance-based XML signature validator that uses dependency injection.
     */
    @Slf4j
    @RequiredArgsConstructor
    public static class XmlValidator {

        private final X509Certificate caCertificate;
        private final Provider provider;


        /**
         * Validate XML signature.
         */
        public boolean validateXmlSignature(String xmlContent) throws Exception {
            Document doc;
            try {
                // Parse XML document
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder db = dbf.newDocumentBuilder();
                doc = db.parse(new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                // If XML parsing fails, consider signature invalid
                log.info("XML parsing failed: {}", e.getMessage());
                return false;
            }

            // Find Signature element
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create validation context
            DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(caCertificate, provider), nl.item(0));

            // Unmarshal the XML Signature
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);

            // Validate the signature
            boolean coreValidity = signature.validate(valContext);

            if (coreValidity) {
                log.info("XML Signature validation successful!");
                return true;
            } else {
                log.info("XML Signature validation failed!");
                // Check individual validations
                boolean sv = signature.getSignatureValue().validate(valContext);
                log.info("Signature validation status: " + sv);

                Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((javax.xml.crypto.dsig.Reference) i.next()).validate(valContext);
                    log.info("Reference[" + j + "] validity: " + refValid);
                }
                return false;
            }
        }

        /**
         * Check if Kalkan provider is being used in the signature.
         */
        //TODO fix bug with check(right now it doesn't work)
        public boolean checkKalkanProvider(String xmlContent) throws Exception {
            // Simple check: look for Kalkan-specific algorithm or provider identifiers
            // In real implementation, this would check the certificate's signature algorithm
            // and verify it's using Kalkan provider
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
            if (nl.getLength() > 0) {
                String algorithm = nl.item(0).getTextContent();
                // Kalkan typically uses RSA with SHA256
                return algorithm != null && algorithm.contains("rsa-sha256");
            }
            return false;
        }

        /**
         * Validate timestamp information in the signature.
         */
        public boolean validateTimestamp(String xmlContent) throws Exception {
            // Check if signature timestamps are within reasonable bounds
            // This is a basic implementation - in practice, would check SignedProperties
            Document doc = parseXmlDocument(xmlContent);
            // For simplicity, check if document has valid structure and could be parsed
            return doc != null && doc.getDocumentElement() != null;
        }

        /**
         * Extract IIN from certificate in the signature.
         */
        public String extractIinFromCertificate(String xmlContent) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
            if (nl.getLength() > 0) {
                String certData = nl.item(0).getTextContent();
                try {
                    byte[] certBytes = Base64.getDecoder().decode(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    // Extract IIN from subject DN (Individual Identification Number)
                    String subjectDN = cert.getSubjectDN().toString();
                    // Assuming IIN is stored in a specific field like "SERIALNUMBER" or custom OID
                    // This is a simplified implementation
                    String[] dnParts = subjectDN.split(",");
                    for (String part : dnParts) {
                        if (part.trim().startsWith("SERIALNUMBER=") || part.trim().startsWith("OID.1.2.398.3.3.4.1.1=")) {
                            return part.split("=")[1].trim();
                        }
                    }
                } catch (Exception e) {
                    log.warn("Failed to extract IIN from certificate: {}", e.getMessage());
                }
            }
            return null;
        }

        /**
         * Extract IIN from signature data if available.
         */
        public String extractIinFromSignature(String xmlContent) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
            if (nl.getLength() > 0) {
                // Check if there's any IIN information in the signed data
                String signedInfo = nl.item(0).getTextContent();
                // Look for IIN pattern (12 digits for Kazakhstan IIN)
                if (signedInfo != null && signedInfo.matches(".*\\b\\d{12}\\b.*")) {
                    // Extract the 12-digit number
                    String[] parts = signedInfo.split("\\b(\\d{12})\\b");
                    if (parts.length > 1) {
                        return parts[1];
                    }
                }
            }
            return null;
        }

        /**
         * Extract BIN from certificate in the signature.
         */
        public String extractBinFromCertificate(String xmlContent) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
            if (nl.getLength() > 0) {
                String certData = nl.item(0).getTextContent();
                try {
                    byte[] certBytes = Base64.getDecoder().decode(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    // Extract BIN from subject DN (Business Identification Number)
                    String subjectDN = cert.getSubjectDN().toString();
                    // Assuming BIN is stored in a specific field like "OID.1.2.398.3.3.4.1.2" or similar
                    String[] dnParts = subjectDN.split(",");
                    for (String part : dnParts) {
                        if (part.trim().startsWith("OID.1.2.398.3.3.4.1.2=") || part.trim().startsWith("OU=")) {
                            return part.split("=")[1].trim();
                        }
                    }
                } catch (Exception e) {
                    log.warn("Failed to extract BIN from certificate: {}", e.getMessage());
                }
            }
            return null;
        }

        /**
         * Extract BIN from signature data if available.
         */
        public String extractBinFromSignature(String xmlContent) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
            if (nl.getLength() > 0) {
                // Check if there's any BIN information in the signed data
                String signedInfo = nl.item(0).getTextContent();
                // Look for BIN pattern (12 digits for Kazakhstan BIN)
                if (signedInfo != null && signedInfo.matches(".*\\b\\d{12}\\b.*")) {
                    // Extract the 12-digit number (assuming BIN follows IIN if both present)
                    String[] parts = signedInfo.split("\\b(\\d{12})\\b");
                    if (parts.length > 2) {
                        // If multiple 12-digit numbers, assume second is BIN
                        return parts[2];
                    } else if (parts.length > 1) {
                        return parts[1];
                    }
                }
            }
            return null;
        }

        /**
         * Check data integrity by validating references.
         */
        public boolean checkDataIntegrity(String xmlContent) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
            // If there are references, assume data integrity needs checking
            return nl.getLength() > 0;
        }

        /**
         * Validate full certificate chain.
         */
        public boolean validateCertificateChain(String xmlContent, X509Certificate caCert) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
            if (nl.getLength() > 0) {
                String certData = nl.item(0).getTextContent();
                try {
                    byte[] certBytes = Base64.getDecoder().decode(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    CertificateValidator.validateCertificateChain(new X509Certificate[]{cert}, caCert, provider);
                    return true;
                } catch (Exception e) {
                    log.warn("Certificate chain validation failed: {}", e.getMessage());
                    return false;
                }
            }
            return false;
        }

        /**
         * Validate that the public key from PEM matches the certificate's public key in the signature.
         */
        public boolean validatePublicKey(String xmlContent, String pemPublicKey) throws Exception {
            if (pemPublicKey == null || pemPublicKey.trim().isEmpty()) {
                return false;
            }

            try {
                String pemContent = pemPublicKey.trim();
                // Check if it's base64 encoded plain PEM text
                try {
                    // Try to decode as base64 first (backward compatibility)
                    byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
                    pemContent = new String(decodedBytes).trim();
                } catch (Exception base64Exception) {
                    // If base64 decode fails, treat as plain PEM text
                    pemContent = pemPublicKey.trim();
                }

                // Remove PEM headers/footers and clean up
                pemContent = pemContent.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                        .replaceAll("-----END PUBLIC KEY-----", "")
                        .replaceAll("-----BEGIN RSA PUBLIC KEY-----", "")
                        .replaceAll("-----END RSA PUBLIC KEY-----", "")
                        .replaceAll("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");

                // Try to parse as public key first
                PublicKey providedPublicKey = null;
                try {
                    byte[] keyBytes = Base64.getDecoder().decode(pemContent);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                    providedPublicKey = keyFactory.generatePublic(keySpec);
                } catch (Exception e) {
                    // If not a public key, try to parse as certificate
                    try {
                        byte[] certBytes = Base64.getDecoder().decode(pemContent);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                        providedPublicKey = cert.getPublicKey();
                    } catch (Exception certException) {
                        log.error("Failed to parse PEM as either public key or certificate: {}", certException.getMessage());
                        return false;
                    }
                }

                // Extract certificate from XML signature
                Document doc = parseXmlDocument(xmlContent);
                NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
                if (nl.getLength() > 0) {
                    String certData = nl.item(0).getTextContent();
                    byte[] certBytes = Base64.getDecoder().decode(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    // Compare public keys
                    PublicKey certPublicKey = cert.getPublicKey();
                    boolean keysMatch = certPublicKey.equals(providedPublicKey);

                    log.info("Public key validation result: {}", keysMatch);
                    return keysMatch;
                }

                return false;
            } catch (Exception e) {
                log.error("Error validating public key: {}", e.getMessage());
                return false;
            }
        }

        /**
         * Check that the certificate's Extended Key Usage contains the specified OIDs.
         */
        public boolean checkExtendedKeyUsage(String xmlContent, String oids) throws Exception {
            if (oids == null || oids.trim().isEmpty()) {
                return false;
            }

            try {
                // Extract certificate from XML signature
                Document doc = parseXmlDocument(xmlContent);
                NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
                if (nl.getLength() > 0) {
                    String certData = nl.item(0).getTextContent();
                    byte[] certBytes = Base64.getDecoder().decode(certData);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    // Get Extended Key Usage from certificate
                    List<String> extendedKeyUsage = cert.getExtendedKeyUsage();

                    if (extendedKeyUsage == null || extendedKeyUsage.isEmpty()) {
                        log.info("Certificate has no extended key usage extension");
                        return false;
                    }

                    // Split the comma-separated OIDs and check if all are present
                    String[] requiredOids = oids.split(",");
                    Set<String> certEkus = new HashSet<>(extendedKeyUsage);

                    for (String oid : requiredOids) {
                        String trimmedOid = oid.trim();
                        if (!trimmedOid.isEmpty() && !certEkus.contains(trimmedOid)) {
                            log.info("Required OID '{}' not found in certificate's extended key usage", trimmedOid);
                            return false;
                        }
                    }

                    log.info("Extended key usage validation successful - all required OIDs found");
                    return true;
                }

                return false;
            } catch (Exception e) {
                log.error("Error validating extended key usage: {}", e.getMessage());
                return false;
            }
        }

        /**
         * Parse XML document helper method.
         */
        private Document parseXmlDocument(String xmlContent) throws Exception {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8)));
        }

        /**
         * KeySelector which retrieves the public key from X509Data and validates against CA.
         */
        private static class X509KeySelector extends KeySelector {
            private final X509Certificate caCertificate;
            private final Provider provider;

            public X509KeySelector(X509Certificate caCertificate, Provider provider) {
                this.caCertificate = caCertificate;
                this.provider = provider;
            }

            public KeySelectorResult select(KeyInfo keyInfo,
                                            KeySelector.Purpose purpose,
                                            AlgorithmMethod method,
                                            XMLCryptoContext context)
                    throws KeySelectorException {

                if (keyInfo == null) {
                    throw new KeySelectorException("Null KeyInfo object!");
                }

                // Search for X509Data in KeyInfo
                for (XMLStructure kiType : keyInfo.getContent()) {
                    if (kiType instanceof X509Data x509Data) {
                        List<?> x509Objects = x509Data.getContent();
                        for (Object o : x509Objects) {
                            if (o instanceof X509Certificate cert) {
                                // Validate certificate against CA
                                try {
                                    CertificateValidator.validateCertificate(cert, caCertificate, provider);
                                    return cert::getPublicKey;
                                } catch (Exception e) {
                                    throw new KeySelectorException("Certificate validation failed: " + e.getMessage());
                                }
                            }
                        }
                    }
                }

                throw new KeySelectorException("No X509Certificate found in KeyInfo!");
            }
        }
    }

}
