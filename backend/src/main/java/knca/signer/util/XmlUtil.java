package knca.signer.util;

import knca.signer.service.CertificateService.SigningEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Utility class for creating XML digital signatures.
 * Implements enveloped XML signatures using javax.xml.crypto.dsig (JDK built-in XML DSig).
 */
public class XmlUtil {

    private static final Logger log = LoggerFactory.getLogger(XmlUtil.class);

    private static final String UTF_8_ENCODING = "utf-8";

    /**
     * Create an XML digital signature for the provided XML content.
     * Creates an enveloped signature that signs the entire document.
     *
     * @param signingEntity The signing entity containing private key and certificate
     * @param xmlSource     The XML content to sign
     * @return The signed XML as a string
     * @throws MarshalException             If XML signing fails
     * @throws XMLSignatureException        If XML signing fails
     * @throws ParserConfigurationException If XML parsing configuration fails
     * @throws IOException                  If XML processing fails
     * @throws SAXException                 If XML parsing fails
     * @throws TransformerException         If XML transformation fails
     */
    public static String createXmlSignature(SigningEntity signingEntity, String xmlSource)
            throws MarshalException, XMLSignatureException, ParserConfigurationException, IOException,
            SAXException, TransformerException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Document document = parseXmlDocument(xmlSource);
        PrivateKey privateKey = signingEntity.getKey();
        X509Certificate certificate = signingEntity.getCertificate();

        // Create XMLSignatureFactory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create DigestMethod
        DigestMethod digestMethod = fac.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", null);

        // Create Transform for enveloped signature
        Transform transform = fac.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec) null);
        Transform c14nTransform = fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", (TransformParameterSpec) null);

        // Create list of transforms
        List<Transform> transformList = Arrays.asList(transform, c14nTransform);

        // Create Reference
        Reference reference = fac.newReference("", digestMethod, transformList, null, null);

        // Create SignedInfo
        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
        SignedInfo signedInfo = fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));

        // Create KeyInfo containing X.509 certificate (end-entity only for signature validation)
        KeyInfoFactory keyInfoFactory = fac.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

        // Create XMLSignature
        XMLSignature xmlSignature = fac.newXMLSignature(signedInfo, keyInfo);

        // Find the root element and create signing context
        Element rootElement = document.getDocumentElement();
        DOMSignContext signContext = new DOMSignContext(privateKey, rootElement);
        signContext.setDefaultNamespacePrefix("ds");

        // Sign the document
        xmlSignature.sign(signContext);

        return serializeXmlDocument(document);
    }

    /**
     * Parse XML string into Document object.
     */
    public static Document parseXmlDocument(String xmlSource)
            throws ParserConfigurationException, SAXException, IOException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setNamespaceAware(true);

        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        return documentBuilder.parse(new ByteArrayInputStream(xmlSource.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Serialize Document object to XML string.
     */
    private static String serializeXmlDocument(Document document) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();

        // For signed documents, don't add indentation to preserve canonical form
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, UTF_8_ENCODING);
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");

        try (StringWriter writer = new StringWriter()) {
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (IOException e) {
            throw new TransformerException("Failed to serialize XML document", e);
        }
    }

    /**
     * Validate XML signature.
     */
    public static boolean validateXmlSignature(String xmlContent) throws Exception {
        Document doc;
        try {
            // Parse XML document
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            doc = db.parse(new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            // If XML parsing fails, consider signature invalid
            log.debug("XML parsing failed: {}", e.getMessage());
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
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

        // Unmarshal the XML Signature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the signature
        boolean coreValidity = signature.validate(valContext);

        if (coreValidity) {
            log.debug("XML Signature validation successful!");
            return true;
        } else {
            log.debug("XML Signature validation failed!");
            // Check individual validations
            boolean sv = signature.getSignatureValue().validate(valContext);
            log.debug("Signature validation status: " + sv);

            Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
            for (int j = 0; i.hasNext(); j++) {
                boolean refValid = ((Reference) i.next()).validate(valContext);
                log.debug("Reference[%d] validity: %s".formatted(j, refValid));
            }
            return false;
        }
    }

    /**
     * Extract IIN from certificate in the signature.
     */
    public static String extractIinFromCertificate(String xmlContent) throws Exception {
        Document doc = parseXmlDocument(xmlContent);
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
        if (nl.getLength() > 0) {
            String certData = nl.item(0).getTextContent();
            try {
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
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
     * Extract BIN from certificate in the signature.
     */
    public static String extractBinFromCertificate(String xmlContent) throws Exception {
        Document doc = parseXmlDocument(xmlContent);
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
        if (nl.getLength() > 0) {
            String certData = nl.item(0).getTextContent();
            try {
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                // Extract IIN from subject DN (Individual Identification Number)
                String subjectDN = cert.getSubjectDN().toString();
                // Assuming IIN is stored in a specific field like "SERIALNUMBER" or custom OID
                // This is a simplified implementation
                String[] dnParts = subjectDN.split(",");
                for (String part : dnParts) {
                    if (part.trim().startsWith("OU=") || part.trim().startsWith("OID.1.2.398.3.3.4.1.2=")) {
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
     * Check if certificate was issued by knca-signer by verifying L=KNCA-SIGNER marker.
     */
    public static boolean checkKncaProvider(String xmlContent) throws Exception {
        log.debug("=== Starting knca-signer provider check ===");
        log.debug("XML content length: {}", xmlContent.length());

        Document doc = parseXmlDocument(xmlContent);
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
        log.debug("Found {} X509Certificate elements in XML", nl.getLength());

        if (nl.getLength() > 0) {
            String certData = nl.item(0).getTextContent();
            log.debug("Raw certificate data (first 100 chars): {}", certData.substring(0, Math.min(100, certData.length())));
            log.debug("Certificate data length: {}", certData.length());

            try {
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                log.debug("Cleaned certificate data length: {}", cleanCertData.length());

                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
                log.debug("Decoded certificate bytes length: {}", certBytes.length);

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                // Check if certificate subject DN contains L=KNCA-SIGNER
                String subjectDN = cert.getSubjectDN().toString();
                boolean hasKncaSignerMarker = subjectDN.contains("L=KNCA-SIGNER");

                log.debug("Certificate subject DN from XML: {}", subjectDN);
                log.debug("Certificate issuer DN: {}", cert.getIssuerDN().toString());
                log.debug("Certificate serial number: {}", cert.getSerialNumber());
                log.debug("Certificate issued by knca-signer: {}", hasKncaSignerMarker);

                // Additional debugging - check all OU values
                String[] dnParts = subjectDN.split(",");
                log.debug("Subject DN parts:");
                for (String part : dnParts) {
                    part = part.trim();
                    if (part.startsWith("L=")) {
                        log.debug("  Found L: {}", part);
                    }
                }

                return hasKncaSignerMarker;
            } catch (Exception e) {
                log.error("Failed to parse certificate for knca-signer check: {}", e.getMessage(), e);
                log.error("Certificate data that failed parsing: {}", certData.substring(0, Math.min(200, certData.length())));
                return false;
            }
        }

        // Additional debugging - check what elements are actually in the XML
        NodeList allElements = doc.getElementsByTagName("*");
        log.warn("No X509Certificate found in XML signature. Found {} total elements:", allElements.getLength());
        for (int i = 0; i < Math.min(10, allElements.getLength()); i++) {
            Element elem = (Element) allElements.item(i);
            log.warn("  Element {}: {} (namespace: {})", i, elem.getTagName(), elem.getNamespaceURI());
        }

        // Check for KeyInfo and X509Data elements
        NodeList keyInfoList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
        log.warn("Found {} KeyInfo elements", keyInfoList.getLength());

        NodeList x509DataList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
        log.warn("Found {} X509Data elements", x509DataList.getLength());

        return false;
    }

    /**
     * Validate that the public key from PEM matches the certificate's public key in the signature.
     */
    public static boolean validatePublicKey(String xmlContent, String pemPublicKey, Provider provider) throws Exception {
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
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                // Compare public keys
                PublicKey certPublicKey = cert.getPublicKey();
                boolean keysMatch = certPublicKey.equals(providedPublicKey);

                log.debug("Public key validation result: {}", keysMatch);
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
    public static boolean checkExtendedKeyUsage(String xmlContent, String oids) throws Exception {
        if (oids == null || oids.trim().isEmpty()) {
            return false;
        }

        try {
            // Extract certificate from XML signature
            Document doc = parseXmlDocument(xmlContent);
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
            if (nl.getLength() > 0) {
                String certData = nl.item(0).getTextContent();
                // Clean the certificate data - remove whitespace
                String cleanCertData = certData.replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanCertData);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                // Get Extended Key Usage from certificate
                List<String> extendedKeyUsage = cert.getExtendedKeyUsage();

                if (extendedKeyUsage == null || extendedKeyUsage.isEmpty()) {
                    log.debug("Certificate has no extended key usage extension");
                    return false;
                }

                // Split the comma-separated OIDs and check if all are present
                String[] requiredOids = oids.split(",");
                Set<String> certEkus = new HashSet<>(extendedKeyUsage);

                for (String oid : requiredOids) {
                    String trimmedOid = oid.trim();
                    if (!trimmedOid.isEmpty() && !certEkus.contains(trimmedOid)) {
                        log.debug("Required OID '{}' not found in certificate's extended key usage", trimmedOid);
                        return false;
                    }
                }

                log.debug("Extended key usage validation successful - all required OIDs found");
                return true;
            }

            return false;
        } catch (Exception e) {
            log.error("Error validating extended key usage: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * KeySelector which retrieves the public key from X509Data.
     */
    private static class X509KeySelector extends KeySelector {

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
                            // Check certificate validity (optional for signature validation)
                            try {
                                cert.checkValidity();
                            } catch (Exception e) {
                                log.warn("Certificate validity check failed: %s, continuing with signature validation".formatted(e.getMessage()));
                            }
                            // Return the public key for signature validation
                            return cert::getPublicKey;
                        } else if (o instanceof byte[] certBytes) {
                            // Handle certificate data as byte array (after XML unmarshaling)
                            try {
                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                                // Return the public key for signature validation
                                return cert::getPublicKey;
                            } catch (Exception e) {
                                log.warn("Failed to parse certificate from byte array: " + e.getMessage());
                            }
                        } else if (o instanceof String certData) {
                            // Handle certificate data as base64 string (after XML unmarshaling)
                            try {
                                byte[] certBytes = Base64.getDecoder().decode(certData);
                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                                // Return the public key for signature validation
                                return cert::getPublicKey;
                            } catch (Exception e) {
                                log.warn("Failed to parse certificate from string: " + e.getMessage());
                            }
                        }
                    }
                }
            }

            throw new KeySelectorException("No X509Certificate found in KeyInfo!");
        }
    }
}
