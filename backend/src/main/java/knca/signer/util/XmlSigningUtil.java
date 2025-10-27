package knca.signer.util;

import knca.signer.service.CertificateService.SigningEntity;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for creating XML digital signatures.
 * Implements enveloped XML signatures using javax.xml.crypto.dsig (JDK built-in XML DSig).
 */
public class XmlSigningUtil {

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
        SignedInfo signedInfo = fac.newSignedInfo(canonicalizationMethod, signatureMethod, java.util.Collections.singletonList(reference));

        // Create KeyInfo containing X.509 certificate
        KeyInfoFactory keyInfoFactory = fac.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(java.util.Collections.singletonList(certificate));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(java.util.Collections.singletonList(x509Data));

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
    private static Document parseXmlDocument(String xmlSource)
            throws ParserConfigurationException, SAXException, IOException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setNamespaceAware(true);

        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        return documentBuilder.parse(new java.io.ByteArrayInputStream(xmlSource.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Serialize Document object to XML string.
     */
    private static String serializeXmlDocument(Document document) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();

        // Configure transformer to preserve formatting
        transformer.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(javax.xml.transform.OutputKeys.ENCODING, UTF_8_ENCODING);

        try (StringWriter writer = new StringWriter()) {
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (IOException e) {
            throw new TransformerException("Failed to serialize XML document", e);
        }
    }

    /**
     * Get XML signature method URI based on certificate signature algorithm OID.
     */
    @Deprecated(forRemoval = true)
    private static String getSignatureMethod(String sigAlgOid) {
        return switch (sigAlgOid) {
            case "1.2.840.113549.1.1.5" -> // SHA1withRSA
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
            case "1.2.840.113549.1.1.11" -> // SHA256withRSA
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            case "1.2.840.10045.4.3.2" -> // SHA256withECDSA
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            case "1.2.803.10045.4.3.2" -> // GOST 34.10-2012 with GOST 34.11-2012-256
                    "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
            default -> throw new IllegalArgumentException("Unsupported signature algorithm OID: " + sigAlgOid);
        };
    }

    /**
     * Get XML digest method URI based on certificate signature algorithm OID.
     */
    @Deprecated(forRemoval = true)
    private static String getDigestMethod(String sigAlgOid) {
        return switch (sigAlgOid) {
            case "1.2.840.113549.1.1.5" -> // SHA1withRSA
                    "http://www.w3.org/2001/04/xmlenc#sha1";
            case "1.2.840.113549.1.1.11" -> // SHA256withRSA
                    "http://www.w3.org/2001/04/xmlenc#sha256";
            case "1.2.840.10045.4.3.2" -> // SHA256withECDSA
                    "http://www.w3.org/2001/04/xmlenc#sha256";
            case "1.2.803.10045.4.3.2" -> // GOST 34.10-2012 with GOST 34.11-2012-256
                    "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
            default -> throw new IllegalArgumentException("Unsupported signature algorithm OID: " + sigAlgOid);
        };
    }
}
