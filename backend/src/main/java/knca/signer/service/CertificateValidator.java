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
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

/**
 * Utility class for certificate validation operations.
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateValidator {

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

}
