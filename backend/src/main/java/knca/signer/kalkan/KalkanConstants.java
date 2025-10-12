package knca.signer.kalkan;

/**
 * Consolidated constants for certificate generation.
 */
public class KalkanConstants {

    public static final String ROOT_SUBJECT_DN = "C=KZ, CN=НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2025";

    // GeneralName constants
    public static class GeneralName {
        public static final int otherName = 0;
        public static final int rfc822Name = 1;
        public static final int dNSName = 2;
        public static final int x400Address = 3;
        public static final int directoryName = 4;
        public static final int ediPartyName = 5;
        public static final int uniformResourceIdentifier = 6;
        public static final int iPAddress = 7;
        public static final int registeredID = 8;
    }

    // KeyUsage constants
    public static class KeyUsage {
        public static final int digitalSignature = 1;
        public static final int keyEncipherment = 2;
        public static final int keyCertSign = 4;
        public static final int cRLSign = 8;
    }

    // KeyPurposeId constants
    public static class KeyPurposeId {

        public static final String id_kp_emailProtection = "1.3.6.1.5.5.7.3.4";
        public static final String id_kp_clientAuthentication = "1.3.6.1.5.5.7.3.2";

    }

    // X509Extensions constants
    public static class X509Extensions {
        public static final String BasicConstraints = "2.5.29.19";
        public static final String KeyUsage = "2.5.29.15";
        public static final String ExtendedKeyUsage = "2.5.29.37";
        public static final String SubjectAlternativeName = "2.5.29.17";
    }
}
