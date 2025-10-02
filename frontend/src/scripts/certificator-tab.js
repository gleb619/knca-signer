export default () => ({
    // Certificate collections
    certificates: {
        ca: {},
        user: {},
        legal: {}
    },

    // UI state
    expandedCAs: {},
    generatingCA: false,
    generatingUser: false,
    generatingLegal: false,

    async init() {
        await this.loadCertificates();
    },

    async loadCertificates() {
        try {
            // Load all certificate types
            const [caResponse, userResponse, legalResponse] = await Promise.all([
                fetch('/api/certificates/ca'),
                fetch('/api/certificates/user'),
                fetch('/api/certificates/legal')
            ]);

            this.certificates.ca = await caResponse.json();
            this.certificates.user = await userResponse.json();
            this.certificates.legal = await legalResponse.json();

            // Initialize expanded state for all CAs
            Object.keys(this.certificates.ca).forEach(caId => {
                this.expandedCAs[caId] = false;
            });

        } catch (error) {
            console.error('Failed to load certificates:', error);
            this.errorMessage = 'Failed to load certificates';
        }
    },

    async generateCA() {
        this.generatingCA = true;
        this.errorMessage = '';
        this.successMessage = '';

        try {
            const response = await fetch('/api/certificates/generate/ca', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();

            // Refresh certificates
            await this.loadCertificates();

            // Expand the newly generated CA
            this.expandedCAs[result.alias] = true;

            this.successMessage = `CA certificate generated successfully: ${result.alias}`;

        } catch (error) {
            console.error('Failed to generate CA:', error);
            this.errorMessage = 'Failed to generate CA certificate';
        } finally {
            this.generatingCA = false;
        }
    },

    async generateUser(caId) {
        this.generatingUser = true;
        this.errorMessage = '';
        this.successMessage = '';

        try {
            const response = await fetch('/api/certificates/generate/user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ caId })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();

            // Refresh certificates
            await this.loadCertificates();

            this.successMessage = `User certificate generated successfully: ${result.alias}`;

        } catch (error) {
            console.error('Failed to generate user certificate:', error);
            this.errorMessage = 'Failed to generate user certificate';
        } finally {
            this.generatingUser = false;
        }
    },

    async generateLegal(caId) {
        this.generatingLegal = true;
        this.errorMessage = '';
        this.successMessage = '';

        try {
            const response = await fetch('/api/certificates/generate/legal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ caId })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();

            // Refresh certificates
            await this.loadCertificates();

            this.successMessage = `Legal certificate generated successfully: ${result.alias}`;

        } catch (error) {
            console.error('Failed to generate legal certificate:', error);
            this.errorMessage = 'Failed to generate legal certificate';
        } finally {
            this.generatingLegal = false;
        }
    },

    toggleCAExpansion(caId) {
        this.expandedCAs[caId] = !this.expandedCAs[caId];
    },

    getUsersForCA(caId) {
        return Object.values(this.certificates.user).filter(cert => cert.caId === caId);
    },

    getLegalsForCA(caId) {
        return Object.values(this.certificates.legal).filter(cert => cert.caId === caId);
    },

    formatDate(dateString) {
        return new Date(dateString).toLocaleDateString();
    },

    copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                this.successMessage = 'Copied to clipboard!';
                setTimeout(() => this.successMessage = '', 3000);
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    },

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            this.successMessage = 'Copied to clipboard!';
            setTimeout(() => this.successMessage = '', 3000);
        } catch (err) {
            this.errorMessage = 'Failed to copy to clipboard';
        }
        document.body.removeChild(textArea);
    },

    clearMessages() {
        this.errorMessage = '';
        this.successMessage = '';
    }
});
