package knca.signer.service;

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
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

/**
 * Instance-based XML signature validator that uses dependency injection.
 */
@Slf4j
@RequiredArgsConstructor
public class XmlValidator {

    private final java.security.Provider provider;
    private final X509Certificate caCertificate;


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
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(caCertificate), nl.item(0));

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
     * KeySelector which retrieves the public key from X509Data and validates against CA.
     */
    private static class X509KeySelector extends KeySelector {
        private final X509Certificate caCertificate;

        public X509KeySelector(X509Certificate caCertificate) {
            this.caCertificate = caCertificate;
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
            Iterator<?> iter = keyInfo.getContent().iterator();
            while (iter.hasNext()) {
                XMLStructure kiType = (XMLStructure) iter.next();
                if (kiType instanceof X509Data x509Data) {
                    List<?> x509Objects = x509Data.getContent();
                    for (Object o : x509Objects) {
                        if (o instanceof X509Certificate cert) {
                            // Validate certificate against CA
                            try {
                                CertificateValidator.validateCertificate(cert, caCertificate);
                                return new KeySelectorResult() {
                                    public java.security.Key getKey() {
                                        return cert.getPublicKey();
                                    }
                                };
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
