const STORAGE_KEY = 'knca_selected_certificates';

export default {
    selectedUserCert: null,
    selectedCaCert: null,
    certCache: {},

    saveToStorage() {
        const data = {
            selectedUserCert: this.selectedUserCert,
            selectedCaCert: this.selectedCaCert,
            timestamp: Date.now()
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    },

    loadFromStorage() {
        console.info("Loading state from storage");

        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                const data = JSON.parse(stored);
                this.selectedUserCert = data.selectedUserCert;
                this.selectedCaCert = data.selectedCaCert;
                // Emit event to restore state
                if (this.selectedUserCert || this.selectedCaCert) {
                    this.emitEvent('certificate-selected');
                }
                this.fetchCaCert();

                return true;
            }
        } catch (e) {
            console.warn('Failed to load certificate selection from localStorage:', e);
        }
        return false;
    },

    selectUserCertificate(cert) {
        this.selectedUserCert = {...cert};
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

    clearSelection() {
        this.selectedUserCert = null;
        this.selectedCaCert = null;
        localStorage.removeItem(STORAGE_KEY);
        this.emitEvent('certificate:cleared');
    },

    emitEvent(eventType) {
        window.dispatchEvent(new CustomEvent(eventType, {
           detail: {
               userCert: this.selectedUserCert,
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
    }
};