package knca.signer.example;

import knca.signer.config.ApplicationConfig;
import knca.signer.service.CertificateValidator;
import knca.signer.service.CertificateValidator.XmlValidator;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;

/**
 * Main entry point for XML signature validation.
 * Now uses the new instance-based XmlValidator.
 */
@Slf4j
public class Validator {

    public static void main(String[] args) {
        if (args.length == 0) {
            log.error("Usage: Validator <xml_content>");
            System.exit(1);
        }

        Validator validator = new Validator();
        validator.work(args[0]);
    }

    public void work(String xmlContent) {
        try {
            // Create provider and load CA certificate using reflection
            Class<?> providerClass = Class.forName("knca.signer.KalkanProvider");
            Object provider = providerClass.getDeclaredConstructor().newInstance();
            ApplicationConfig.CertificateConfig config = new ApplicationConfig.CertificateConfig(
                    "certs/",
                    "certs/ca.crt",
                    2048,
                    "RSA",
                    "1.2.840.113549.1.1.11",
                    "123456",
                    10,
                    1
            );
            X509Certificate caCertificate = CertificateValidator.loadCACertificate(config.getCaCertPath());

            // Create and run XML validator
            XmlValidator xmlValidator = new XmlValidator(caCertificate);
            boolean valid = xmlValidator.validateXmlSignature(xmlContent);

            log.info("Validation result: " + valid);
        } catch (Exception e) {
            log.error("Validation failed: %s".formatted(e.getMessage()), e);
        }
    }
}
