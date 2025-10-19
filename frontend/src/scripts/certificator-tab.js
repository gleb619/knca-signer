import * as api from './certificator/api.js';
import * as utils from './certificator/utils.js';

export default () => ({
    // Certificate collections - now hierarchical array structure
    /* Structure: Array of CA objects, each containing CA info and its user/legal certificates */
    certificates: [],

    // UI state
    generatingCA: false,
    generatingUser: false,
    generatingLegal: false,

    // Form data
    newCAAlias: '',

    activeSubTab: 'create',

    async init() {
        await this.loadCertificates();
    },

    // Spread imported functionalities
    ...api,
    ...utils,

    async generateUser(caId) {
        return this.generateCertificate('user', '/api/certificates/generate/user', { caId });
    },

    async generateLegal(caId) {
        return this.generateCertificate('legal', '/api/certificates/generate/legal', { caId });
    },

    // Enhanced action methods for Alpine.js component context
    async copyToClipboardHandler(text) {
        try {
            await this.copyToClipboard(text);
            this.addNotification('success', 'Copied to clipboard!');
        } catch (err) {
            this.addNotification('error', 'Failed to copy to clipboard');
        }
    },

    selectUserCertificate(cert) {
        const req = {...cert};
        req.initials = this.generateInitials(cert);
        req.fullName = this.getFullName(cert) || cert.alias;
        req.notAfterDate = this.formatDate(cert.notAfter);
        this.$store.certificateStore.selectUserCertificate(req);
    },

    selectLegalCertificate(cert) {
        const req = {...cert};
        req.initials = this.generateInitials(cert);
        req.fullName = this.getFullName(cert) || cert.alias;
        req.organization = this.getCertificateDetails(cert).organization || cert.alias;
        req.notAfterDate = this.formatDate(cert.notAfter);
        this.$store.certificateStore.selectLegalCertificate(req);
    },

    selectCaCertificate(cert) {
        const req = {...cert};
        req.notAfterDate = this.formatDate(cert.notAfter);
        this.$store.certificateStore.selectCaCertificate(req);
    },

});
