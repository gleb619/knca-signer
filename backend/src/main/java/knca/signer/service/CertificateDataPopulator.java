package knca.signer.service;

import java.util.Random;

/**
 * Utility class for generating fake Kazakh certificate data.
 */
public class CertificateDataPopulator {

    // OIDs for Kazakh extensions
    public static final String IIN_OID = "1.2.398.3.3.4.1.1";
    public static final String BIN_OID = "1.2.398.3.3.4.1.2";
    private static final Random random = new Random();

    // Kazakh names data
    private static final String[] KAZAKH_SURNAMES = {
            "ҚҰНАНБАЙ", "БӨКЕЙХАН", "БАЙТҰРСЫН", "ДУЛАТ", "ШОҚАЙ", "ӘЛІХАН", "АХМЕТ", "МҰСТАФА", "МІРЖАҚЫП", "НҰРМҰХАМЕД",
            "ТӨЛЕУ", "СЕЙІТҚҰЛ", "ЖАНБОЛАТ", "ҚАЙРАТ", "ЕРЖАН", "СЕРІК", "ҚАЛДЫБАЙ", "БЕКЖАН", "НҰРБОЛ", "АЙДОС"
    };
    private static final String[] KAZAKH_GIVEN_NAMES = {
            "АБАЙ", "ӘЛИХАН", "АХМЕТ", "МІРЖАҚЫП", "МҰСТАФА", "НҰРМҰХАМЕД", "БАЙТҰРСЫН", "ДУЛАТ", "ШОҚАЙ", "ҚҰНАНБАЙ",
            "ЕРЖАН", "АЙДОС", "БЕКЖАН", "ҚАЙРАТ", "ТӨЛЕУ", "СЕРІК", "ЖАНБОЛАТ", "АРМАН", "ДӘУРЕН", "САҒАТ"
    };
    private static final String[] KAZAKH_PATRONYMICS = {
            "KUNANBAIULY", "NURMUHAMEDULY", "BAITURSYNULY", "DULATULY", "SHOKAIULY", "ELIKHANULY", "AKHMETULY", "MUSTAFAULY", "MIRZHAKYPULY", "ABAIULY",
            "ERZHANULY", "AIDOSULY", "BEKZHANULY", "KAIRATULY", "TOLEUULY", "SERIKULY", "ZHANBOLATULY", "ARMANULY", "DAURENULY", "SAGATULY"
    };
    private static final String[] KAZAKH_COMPANIES = {
            "АЛАША ГРУППП PLUS", "ҚАЗАҚСТАН ROAD СЕРВИСІ", "ҚАЗНҰНАЙ ЭНЕРДЖИ", "КАЗАЭЙР ЛОУКОСТЕР LINES", "ҚАРЖЫ BANK ҚАЗАҚСТАН",
            "ГҮЛ-ДАН АТЫНДАҒЫ ORDSTROY", "ҚАЗНЕТЕХНОЛОГИЯ LAB", "PUDGE БАТЫР ШЫМКЕНТТЕН", "ТАЛГАР БАНКІ 360", "ҚАЗНЕТРАНС LOGISTICS HUB"
    };
    private static final String[] COMPANY_ROLES = {
            "CHIEF_EXECUTIVE_OFFICER", "CHIEF_FINANCIAL_OFFICER", "CHIEF_TECHNOLOGY_OFFICER", "CHIEF_OPERATING_OFFICER",
            "MANAGING_DIRECTOR", "DEPUTY_DIRECTOR", "HEAD_OF_DEPARTMENT", "PROJECT_MANAGER", "TEAM_LEAD", "SOFTWARE_ENGINEER",
            "BUSINESS_ANALYST", "QUALITY_ASSURANCE_ENGINEER", "HR_MANAGER", "RECRUITER", "MARKETING_SPECIALIST",
            "SALES_MANAGER", "CUSTOMER_SUPPORT_SPECIALIST", "ACCOUNTANT", "LEGAL_ADVISOR", "INTERN"
    };
    private static final String[] BUSINESS_CATEGORY = {
            "KS00001", "KS00002", "KS00003", "KS00004", "KS00005",
            "KS01001", "KS01002", "KS01003", "KS01004", "KS01005",
            "KS02001", "KS02002", "KS02003", "KS02004", "KS02005",
            "KS03001", "KS03002", "KS03003", "KS03004", "KS03005"
    };
    private static final String[] EMAIL_DOMAINS = {
            "gmail.com", "mail.kz", "yandex.kz", "outlook.com"
    };
    private static final String[] KAZAKH_CA_NAMES = {
            "НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2025",
            "НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2026",
            "НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2027",
            "ҚАЗАҚСТАН РЕСПУБЛИКАСЫНЫҢ КУӘЛАНДЫРУШЫ ОРТАЛЫҒЫ TEST 2028",
            "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) TEST 2029",
            "БІРІККЕН КУӘЛАНДЫРУШЫ ОРТАЛЫҚ ҚАЗАҚСТАН TEST 2030"
    };

    /**
     * Generate a random 12-digit IIN (Individual Identification Number).
     */
    public static String populateIIN() {
        return generateNumber("1");
    }

    /**
     * Generate a random 12-digit BIN (Business Identification Number).
     * Same format as IIN.
     */
    public static String populateBIN() {
        return generateNumber("0");
    }

    /**
     * Generate a random Kazakh company name.
     */
    public static String populateCompany() {
        return KAZAKH_COMPANIES[random.nextInt(KAZAKH_COMPANIES.length)] + " TEST CERT";
    }

    /**
     * Generate a random alphanumeric string of specified length.
     */
    public static String populateRandomAlphanumeric(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Generate a random email address.
     */
    public static String populateEmail() {
        String local = "user" + populateRandomAlphanumeric(8);
        String domain = EMAIL_DOMAINS[random.nextInt(EMAIL_DOMAINS.length)];
        return "%s@%s".formatted(local, domain);
    }

    /**
     * Generate subject DN for a CA certificate with random selection from available names.
     */
    public static String populateCASubjectDN() {
        String caName = KAZAKH_CA_NAMES[random.nextInt(KAZAKH_CA_NAMES.length)];
        return "C=KZ, CN=%s, L=KNCA-SIGNER".formatted(caName);
    }

    /**
     * Generate subject DN for an individual certificate.
     */
    public static String populateIndividualSubjectDN() {
        String surname = KAZAKH_SURNAMES[random.nextInt(KAZAKH_SURNAMES.length)];
        String givenName = KAZAKH_GIVEN_NAMES[random.nextInt(KAZAKH_GIVEN_NAMES.length)];
        String patronymic = KAZAKH_PATRONYMICS[random.nextInt(KAZAKH_PATRONYMICS.length)];
        String fullName = givenName + " " + surname;
        String iin = populateIIN();
        String email = populateEmail();
        return "CN=%s, SURNAME=%s, SN=IIN%s, C=KZ, L=KNCA-SIGNER, G=%s, emailAddress=%s".formatted(fullName, surname, iin, patronymic, email);
    }

    /**
     * Generate subject DN for a legal entity certificate.
     */
    public static String populateLegalEntitySubjectDN() {
        String surname = KAZAKH_SURNAMES[random.nextInt(KAZAKH_SURNAMES.length)];
        String givenName = KAZAKH_GIVEN_NAMES[random.nextInt(KAZAKH_GIVEN_NAMES.length)];
        String patronymic = KAZAKH_PATRONYMICS[random.nextInt(KAZAKH_PATRONYMICS.length)];
        String fullName = givenName + " " + surname;
        String company = KAZAKH_COMPANIES[random.nextInt(KAZAKH_COMPANIES.length)] + " TEST CERT";
        String bin = populateBIN();
        String iin = populateIIN();
        String email = populateEmail();
        String businessCategory = BUSINESS_CATEGORY[random.nextInt(BUSINESS_CATEGORY.length)];
        String dc = COMPANY_ROLES[random.nextInt(COMPANY_ROLES.length)];
        return "CN=%s, SURNAME=%s, SN=IIN%s, C=KZ, O=%s, L=KNCA-SIGNER, OU=BIN%s, BusinessCategory=%s, G=%s, DC=%s, emailAddress=%s".formatted(
                fullName, surname, iin, company, bin, businessCategory, patronymic, dc, email);
    }

    /**
     * Extract email from subject DN.
     */
    public static String extractEmail(String dn) {
        String[] parts = dn.split(", ");
        for (String part : parts) {
            if (part.startsWith("emailAddress=")) {
                return part.substring("emailAddress=".length());
            }
        }
        return "user@example.com";
    }

    /**
     * Extract IIN from subject DN.
     */
    public static String extractIIN(String dn) {
        String[] parts = dn.split(", ");
        for (String part : parts) {
            if (part.startsWith("SN=IIN")) {
                return part.substring("SN=IIN".length());
            }
        }
        return "123456789012";
    }

    /**
     * Generate subject DN for a legal entity certificate with specified company and BIN.
     */
    public static String populateLegalEntitySubjectDN(String company, String bin) {
        String surname = KAZAKH_SURNAMES[random.nextInt(KAZAKH_SURNAMES.length)];
        String givenName = KAZAKH_GIVEN_NAMES[random.nextInt(KAZAKH_GIVEN_NAMES.length)];
        String patronymic = KAZAKH_PATRONYMICS[random.nextInt(KAZAKH_PATRONYMICS.length)];
        String fullName = givenName + " " + surname;
        String iin = populateIIN();
        String email = populateEmail();
        String businessCategory = BUSINESS_CATEGORY[random.nextInt(BUSINESS_CATEGORY.length)];
        String dc = COMPANY_ROLES[random.nextInt(COMPANY_ROLES.length)];
        return "CN=%s, SURNAME=%s, SN=IIN%s, C=KZ, O=%s, L=KNCA-SIGNER, OU=BIN%s, BusinessCategory=%s, G=%s, DC=%s, emailAddress=%s".formatted(
                fullName, surname, iin, company, bin, businessCategory, patronymic, dc, email);
    }

    /**
     * Extract BIN from subject DN.
     */
    public static String extractBIN(String dn) {
        String[] parts = dn.split(", ");
        for (String part : parts) {
            if (part.startsWith("OU=BIN")) {
                return part.substring("OU=BIN".length());
            }
        }
        return null;
    }

    /**
     * Generates a 12-digit number by appending 11 random digits to the provided first digit.
     *
     * @param firstNumber the first digit(s) of the number (should be 1 digit for IIN, 0 for BIN)
     * @return a 12-digit string representation of the generated number
     */
    private static String generateNumber(String firstNumber) {
        StringBuilder sb = new StringBuilder(firstNumber);
        for (int i = 0; i < 11; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

}
