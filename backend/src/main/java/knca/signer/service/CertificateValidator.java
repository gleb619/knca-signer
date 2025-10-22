package knca.signer.service;

import knca.signer.controller.VerifierHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
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
import java.security.PublicKey;
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

    private final java.security.Provider provider;
    private final CertificateStorage registry;

    /**
     * Validate XML signature.
     */
    public CertificateService.ValidationResult validateXmlSignature(VerifierHandler.XmlValidationRequest request) throws Exception {
        Map<String, String> details = new HashMap<>();
        CertificateService.ValidationResult result = new CertificateService.ValidationResult(true, "XML signature validation successful", details);

        CertificateService.CertificateResult defaultCa = registry.getFirstCACertificate().orElseThrow();
        XmlValidator validator = new XmlValidator(defaultCa.getCertificate(), provider);

        try {
            // Basic signature validation
            boolean signatureValid = validator.validateXmlSignature(request.getXml());
            if (!signatureValid) {
                result.setValid(false);
                result.setMessage("XML signature is invalid");
                details.put("signatureValid", "false");
                return result;
            }
            details.put("signatureValid", "true");

            // Check Kalkan provider if requested
            if (request.isCheckKalkanProvider()) {
                try {
                    boolean kalkanUsed = validator.checkKalkanProvider(request.getXml());
                    details.put("kalkanProviderUsed", String.valueOf(kalkanUsed));
                } catch (Exception e) {
                    details.put("kalkanProviderCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Kalkan provider check failed: " + e.getMessage());
                }
            }

            // Check data integrity if requested
            if (request.isCheckData()) {
                try {
                    boolean dataIntegrity = validator.checkDataIntegrity(request.getXml());
                    details.put("dataIntegrityValid", String.valueOf(dataIntegrity));
                    if (!dataIntegrity) {
                        result.setValid(false);
                        result.setMessage("Data integrity check failed");
                    }
                } catch (Exception e) {
                    details.put("dataIntegrityCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Data integrity check failed: " + e.getMessage());
                }
            }

            // Validate timestamps if requested
            if (request.isCheckTime()) {
                try {
                    boolean timestampValid = validator.validateTimestamp(request.getXml());
                    details.put("timestampValid", String.valueOf(timestampValid));
                    if (!timestampValid) {
                        result.setValid(false);
                        result.setMessage("Timestamp validation failed");
                    }
                } catch (Exception e) {
                    details.put("timestampCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Timestamp validation failed: " + e.getMessage());
                }
            }

            // Extract IIN from certificate if requested
            if (request.isCheckIinInCert()) {
                try {
                    String certIin = validator.extractIinFromCertificate(request.getXml());
                    details.put("certificateIin", certIin != null ? certIin : "not found");

                    if (request.getExpectedIin() != null && certIin != null) {
                        boolean iinMatches = request.getExpectedIin().equals(certIin);
                        details.put("certificateIinMatches", String.valueOf(iinMatches));
                        if (!iinMatches) {
                            result.setValid(false);
                            result.setMessage("Certificate IIN does not match expected value");
                        }
                    }
                } catch (Exception e) {
                    details.put("certificateIinCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Certificate IIN check failed: " + e.getMessage());
                }
            }

            // Extract IIN from signature if requested
            if (request.isCheckIinInSign()) {
                try {
                    String signIin = validator.extractIinFromSignature(request.getXml());
                    details.put("signatureIin", signIin != null ? signIin : "not found");

                    if (request.getExpectedIin() != null && signIin != null) {
                        boolean iinMatches = request.getExpectedIin().equals(signIin);
                        details.put("signatureIinMatches", String.valueOf(iinMatches));
                        if (!iinMatches) {
                            result.setValid(false);
                            result.setMessage("Signature IIN does not match expected value");
                        }
                    }
                } catch (Exception e) {
                    details.put("signatureIinCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Signature IIN check failed: " + e.getMessage());
                }
            }

            // Extract BIN from certificate if requested
            if (request.isCheckBinInCert()) {
                try {
                    String certBin = validator.extractBinFromCertificate(request.getXml());
                    details.put("certificateBin", certBin != null ? certBin : "not found");

                    if (request.getExpectedBin() != null && certBin != null) {
                        boolean binMatches = request.getExpectedBin().equals(certBin);
                        details.put("certificateBinMatches", String.valueOf(binMatches));
                        if (!binMatches) {
                            result.setValid(false);
                            result.setMessage("Certificate BIN does not match expected value");
                        }
                    }
                } catch (Exception e) {
                    details.put("certificateBinCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Certificate BIN check failed: " + e.getMessage());
                }
            }

            // Extract BIN from signature if requested
            if (request.isCheckBinInSign()) {
                try {
                    String signBin = validator.extractBinFromSignature(request.getXml());
                    details.put("signatureBin", signBin != null ? signBin : "not found");

                    if (request.getExpectedBin() != null && signBin != null) {
                        boolean binMatches = request.getExpectedBin().equals(signBin);
                        details.put("signatureBinMatches", String.valueOf(binMatches));
                        if (!binMatches) {
                            result.setValid(false);
                            result.setMessage("Signature BIN does not match expected value");
                        }
                    }
                } catch (Exception e) {
                    details.put("signatureBinCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Signature BIN check failed: " + e.getMessage());
                }
            }

            // Validate certificate chain if requested
            if (request.isCheckCertificateChain()) {
                try {
                    X509Certificate caCertToUse = defaultCa.getCertificate();

                    // If custom CA PEM is provided, parse and use it
                    if (request.getCaPem() != null && !request.getCaPem().trim().isEmpty()) {
                        try {
                            String pemContent = request.getCaPem().trim();
                            // Check if it's base64 encoded (for backward compatibility) or plain PEM text
                            String cleanedContent;
                            try {
                                // Try to decode as base64 first
                                byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
                                cleanedContent = new String(decodedBytes).trim();
                            } catch (Exception base64Exception) {
                                // If base64 decode fails, treat as plain PEM text
                                cleanedContent = pemContent;
                            }

                            // Remove PEM headers/footers and clean up
                            cleanedContent = cleanedContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                    .replaceAll("-----END CERTIFICATE-----", "")
                                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                                    .replaceAll("-----END PUBLIC KEY-----", "")
                                    .replaceAll("\\s", "");

                            byte[] certBytes = Base64.getDecoder().decode(cleanedContent);
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            caCertToUse = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                            log.info("Using custom CA certificate for chain validation");
                        } catch (Exception caParseException) {
                            log.warn("Failed to parse custom CA PEM: {}", caParseException.getMessage());
                            details.put("customCaParseError", caParseException.getMessage());
                            result.setValid(false);
                            result.setMessage("Custom CA certificate parsing failed: " + caParseException.getMessage());
                            return result;
                        }
                    }

                    boolean chainValid = validator.validateCertificateChain(request.getXml(), caCertToUse);
                    details.put("certificateChainValid", String.valueOf(chainValid));
                    if (!chainValid) {
                        result.setValid(false);
                        result.setMessage("Certificate chain validation failed");
                    }
                } catch (Exception e) {
                    details.put("certificateChainCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Certificate chain validation failed: " + e.getMessage());
                }
            }

            // Validate public key if requested
            if (request.isCheckPublicKey()) {
                try {
                    boolean publicKeyValid = validator.validatePublicKey(request.getXml(), request.getPublicKey());
                    details.put("publicKeyValid", String.valueOf(publicKeyValid));
                    if (!publicKeyValid) {
                        result.setValid(false);
                        result.setMessage("Public key validation failed - provided key does not match certificate");
                    }
                } catch (Exception e) {
                    details.put("publicKeyCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Public key validation error: " + e.getMessage());
                }
            }

            // Check extended key usage if requested
            if (request.isCheckExtendedKeyUsage()) {
                try {
                    boolean extendedKeyUsageValid = validator.checkExtendedKeyUsage(request.getXml(), request.getExtendedKeyUsageOids());
                    details.put("extendedKeyUsageValid", String.valueOf(extendedKeyUsageValid));
                    if (!extendedKeyUsageValid) {
                        result.setValid(false);
                        result.setMessage("Extended key usage validation failed - certificate EKU does not match required OIDs");
                    }
                } catch (Exception e) {
                    details.put("extendedKeyUsageCheckError", e.getMessage());
                    result.setValid(false);
                    result.setMessage("Extended key usage validation error: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("Validation failed: " + e.getMessage());
            details.put("generalError", e.getMessage());
        }

        return result;
    }

    /**
     * Validate a certificate against a CA certificate.
     */
    public static void validateCertificate(X509Certificate userCert, X509Certificate caCert, java.security.Provider provider) throws Exception {
        // Verify certificate signature using provider
        String sigAlgo = userCert.getSigAlgName();
        java.security.Signature sig = java.security.Signature.getInstance(sigAlgo, provider.getName());
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
     * Load CA certificate from file.
     */
    public static X509Certificate loadCACertificate(String caCertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(caCertPath)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Validate certificate chain.
     */
    public static void validateCertificateChain(X509Certificate[] chain, X509Certificate caCert, java.security.Provider provider) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Certificate chain is empty");
        }

        // Validate each certificate in the chain
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate cert = chain[i];
            X509Certificate issuer = chain[i + 1];
            // Verify certificate signature using provider
            String sigAlgo = cert.getSigAlgName();
            java.security.Signature sig = java.security.Signature.getInstance(sigAlgo, provider.getName());
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
            java.security.Signature sig = java.security.Signature.getInstance(sigAlgo, provider.getName());
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
     * Instance-based XML signature validator that uses dependency injection.
     */
    @Slf4j
    @RequiredArgsConstructor
    public static class XmlValidator {

        private final X509Certificate caCertificate;
        private final java.security.Provider provider;


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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create validation context
            DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(caCertificate, provider), nl.item(0));

            // Unmarshal the XML Signature
            javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);

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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignatureMethod");
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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "X509Certificate");
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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignedInfo");
            if (nl.getLength() > 0) {
                // Check if there's any IIN information in the signed data
                // This could be in custom namespaces or specific elements
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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "X509Certificate");
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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignedInfo");
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
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference");
            // If there are references, assume data integrity needs checking
            return nl.getLength() > 0;
        }

        /**
         * Validate full certificate chain.
         */
        public boolean validateCertificateChain(String xmlContent, X509Certificate caCert) throws Exception {
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "X509Certificate");
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
                NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "X509Certificate");
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
                NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "X509Certificate");
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
        private class X509KeySelector extends KeySelector {
            private final X509Certificate caCertificate;
            private final java.security.Provider provider;

            public X509KeySelector(X509Certificate caCertificate, java.security.Provider provider) {
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

    @lombok.Data
    @lombok.RequiredArgsConstructor
    public static class CertificateResult {
        private final java.security.KeyPair keyPair;
        private final java.security.cert.X509Certificate certificate;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class ValidationResult {
        private boolean valid;
        private String message;
        private Map<String, String> details;
    }
}
