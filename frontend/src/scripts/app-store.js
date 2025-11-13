const STORAGE_KEY = 'knca_selected_certificates';

export default {
    selectedUserCert: null,
    selectedLegalCert: null,
    selectedCaCert: null,
    certCache: {},

    saveToStorage() {
        const data = {
            selectedUserCert: this.selectedUserCert,
            selectedLegalCert: this.selectedLegalCert,
            selectedCaCert: this.selectedCaCert,
            timestamp: Date.now()
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    },

    async loadFromStorage() {
        console.info("Loading state from storage");

        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                const data = JSON.parse(stored);
                this.selectedUserCert = data.selectedUserCert;
                this.selectedLegalCert = data.selectedLegalCert;
                this.selectedCaCert = data.selectedCaCert;
                // Emit event to restore state
                if (this.selectedUserCert || this.selectedLegalCert || this.selectedCaCert) {
                    this.emitEvent('certificate-selected');
                }
                await this.fetchCaCert();
                return true;
            }
        } catch (e) {
            console.warn('Failed to load certificate selection from localStorage:', e);
        }
        return false;
    },

    selectUserCertificate(cert) {
        this.selectedUserCert = {...cert};
        this.selectedLegalCert = null;
        this.saveToStorage();
        this.emitEvent('certificate-selected');
    },

    selectLegalCertificate(cert) {
        this.selectedLegalCert = {...cert};
        this.selectedUserCert = null;
        this.saveToStorage();
        this.emitEvent('certificate-selected');
    },

    selectCaCertificate(caCert) {
        this.selectedCaCert = {...caCert};
        this.saveToStorage();
        this.fetchCaCert();
    },

    clearUserSelection() {
        this.selectedUserCert = null;
        this.saveToStorage();
        this.emitEvent('certificate:cleared');
    },

    clearLegalSelection() {
        this.selectedLegalCert = null;
        this.saveToStorage();
        this.emitEvent('certificate:cleared');
    },

    clearSelection() {
        this.selectedUserCert = null;
        this.selectedLegalCert = null;
        this.selectedCaCert = null;
        localStorage.removeItem(STORAGE_KEY);
        this.emitEvent('certificate:cleared');
    },

    emitEvent(eventType) {
        window.dispatchEvent(new CustomEvent(eventType, {
           detail: {
               userCert: this.selectedUserCert,
               legalCert: this.selectedLegalCert,
               caCert: this.selectedCaCert
           }
        }));
    },

    async fetchCaCert() {
        const caAlias = this.selectedCaCert?.alias;
        if(!caAlias) return null;

        if (this.certCache[caAlias]) {
            return this.certCache[caAlias];
        }

        try {
            const response = await fetch(`/api/certificates/download/${caAlias}/pem`);
            if (response.ok) {
                const pem = await response.text();
                this.certCache[caAlias] = pem;
                return pem;
            }
        } catch (err) {
            console.warn('Failed to fetch CA certificate:', err);
        }

        return null;
    },

    async fetchUserCert() {
        const certAlias = this.selectedUserCert?.alias || this.selectedLegalCert?.alias;
        if(!certAlias) return null;

        if (this.certCache[certAlias]) {
            return this.certCache[certAlias];
        }

        try {
            const response = await fetch(`/api/certificates/download/${certAlias}/pem`);
            if (response.ok) {
                const pem = await response.text();
                this.certCache[certAlias] = pem;
                return pem;
            }
        } catch (err) {
            console.warn('Failed to fetch user certificate:', err);
        }

        return null;
    }
};
