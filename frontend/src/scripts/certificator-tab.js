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

    // Spread utility functions
    ...utils,

    // Wrapper functions for API calls with proper this context handling
    async loadCertificates() {
        try {
            this.certificates = await api.loadCertificates();
            if (this.certificates.length > 0) {
                this.activeSubTab = this.certificates[0].alias;
            }
        } catch (error) {
            this.certificates = [];
            this.addNotification('error', 'Failed to load certificates');
        }
    },

    async generateCA() {
        this.generatingCA = true;

        try {
            const result = await api.generateCACertificate(this.newCAAlias);

            // Refresh certificates
            await this.loadCertificates();

            // Switch to the newly created CA view
            this.activeSubTab = result.alias;

            this.addNotification('success', `CA certificate generated successfully: ${result.alias}`);

            // Clear the input field
            this.newCAAlias = '';

        } catch (error) {
            console.error('Failed to generate CA:', error);
            this.addNotification('error', 'Failed to generate CA certificate');
        } finally {
            this.generatingCA = false;
        }
    },

    async generateUser(caId) {
        this.generatingUser = true;

        try {
            const result = await api.generateUserCertificate(caId);

            // Refresh certificates
            await this.loadCertificates();

            this.addNotification('success', `User certificate generated successfully: ${result.alias}`);

            return result;

        } catch (error) {
            console.error('Failed to generate user certificate:', error);
            this.addNotification('error', 'Failed to generate user certificate');
            throw error;
        } finally {
            this.generatingUser = false;
        }
    },

    async generateLegal(caId) {
        this.generatingLegal = true;

        try {
            const result = await api.generateLegalCertificate(caId);

            // Refresh certificates
            await this.loadCertificates();

            this.addNotification('success', `Legal certificate generated successfully: ${result.alias}`);

            return result;

        } catch (error) {
            console.error('Failed to generate legal certificate:', error);
            this.addNotification('error', 'Failed to generate legal certificate');
            throw error;
        } finally {
            this.generatingLegal = false;
        }
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

    async downloadCertificate(alias, format) {
        try {
            const filename = await api.downloadCertificate(alias, format);
            this.addNotification('success', `Certificate downloaded successfully: ${filename}`);
        } catch (error) {
            console.error('Download failed:', error);
            this.addNotification('error', `Download failed: ${error.message}`);
        }
    },

});
