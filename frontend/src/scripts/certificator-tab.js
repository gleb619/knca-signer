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

    buildHierarchicalFromFlat(flatCertificates) {
        const caMap = new Map();
        const result = [];

        for (const cert of flatCertificates) {
            switch (cert.type) {
                case 'CA':
                    const caStructure = {
                        ca: cert,
                        userCertificates: [],
                        legalCertificates: [],
                        alias: cert.alias || cert.subject
                    };
                    caMap.set(cert.alias || cert.subject, caStructure);
                    result.push(caStructure);
                    break;
                case 'USER':
                    const userCaAlias = cert.issuer || cert.caId; // Assume caId or extract from issuer
                    if (caMap.has(userCaAlias)) {
                        caMap.get(userCaAlias).userCertificates.push(cert);
                    }
                    break;
                case 'LEGAL':
                    const legalCaAlias = cert.issuer || cert.caId;
                    if (caMap.has(legalCaAlias)) {
                        caMap.get(legalCaAlias).legalCertificates.push(cert);
                    }
                    break;
            }
        }

        return result;
    },

    async loadCertificates() {
        try {
            // First, load CA certificates
            const caResponse = await fetch('/api/certificates/ca');
            const caData = await caResponse.json();

            // Build hierarchical structure: array of CA objects with nested user/legal certificates
            this.certificates = [];

            for (const caCert of caData.certificates) {
                // Create CA structure with its certificates
                const caStructure = {
                    ca: caCert,
                    userCertificates: [],
                    legalCertificates: [],
                    alias: caCert.alias // convenience property
                };

                // Load user certificates for this CA
                try {
                    const userResponse = await fetch(`/api/certificates/user?caId=${caCert.alias}`);
                    const userData = await userResponse.json();
                    caStructure.userCertificates = userData.certificates;
                } catch (e) {
                    console.warn(`Failed to load user certificates for CA ${caCert.alias}:`, e);
                }

                // Load legal certificates for this CA
                try {
                    const legalResponse = await fetch(`/api/certificates/legal?caId=${caCert.alias}`);
                    const legalData = await legalResponse.json();
                    caStructure.legalCertificates = legalData.certificates;
                } catch (e) {
                    console.warn(`Failed to load legal certificates for CA ${caCert.alias}:`, e);
                }

                this.certificates.push(caStructure);
            }

            if(this.certificates) {
                this.activeSubTab = this.certificates[0].alias;
            }

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
            // Build URL with optional alias parameter
            const url = this.newCAAlias.trim()
                ? `/api/certificates/generate/ca?alias=${encodeURIComponent(this.newCAAlias.trim())}`
                : '/api/certificates/generate/ca';

            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();

            // Refresh certificates
            await this.loadCertificates();

            // Switch to the newly created CA view
            this.activeSubTab = result.alias;

            this.successMessage = `CA certificate generated successfully: ${result.alias}`;

            // Clear the input field
            this.newCAAlias = '';

            // Auto-clear success message after 5 seconds
            setTimeout(() => {
                if (this.successMessage === `CA certificate generated successfully: ${result.alias}`) {
                    this.successMessage = '';
                }
            }, 5000);

        } catch (error) {
            console.error('Failed to generate CA:', error);
            this.errorMessage = 'Failed to generate CA certificate';

            // Auto-clear error message after 8 seconds
            setTimeout(() => {
                this.errorMessage = '';
            }, 8000);
        } finally {
            this.generatingCA = false;
        }
    },

    // Common certificate generation pattern
    async generateCertificate(type, url, body = null) {
        const loadingFlag = `generating${type.charAt(0).toUpperCase() + type.slice(1)}`;

        this[loadingFlag] = true;
        this.errorMessage = '';
        this.successMessage = '';

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: body ? JSON.stringify(body) : null
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();

            // Refresh certificates
            await this.loadCertificates();

            this.successMessage = `${type === 'CA' ? 'CA' : type.charAt(0).toUpperCase() + type.slice(1).toLowerCase()} certificate generated successfully: ${result.alias}`;

            // Auto-clear success message after 5 seconds
            const successMsg = this.successMessage;
            setTimeout(() => {
                if (this.successMessage === successMsg) {
                    this.successMessage = '';
                }
            }, 5000);

            return result;

        } catch (error) {
            console.error(`Failed to generate ${type.toLowerCase()} certificate:`, error);
            this.errorMessage = `Failed to generate ${type.toLowerCase()} certificate`;

            // Auto-clear error message after 8 seconds
            setTimeout(() => {
                this.errorMessage = '';
            }, 8000);

            throw error;
        } finally {
            this[loadingFlag] = false;
        }
    },

    async generateUser(caId) {
        return this.generateCertificate('user', '/api/certificates/generate/user', { caId });
    },

    async generateLegal(caId) {
        return this.generateCertificate('legal', '/api/certificates/generate/legal', { caId });
    },

    // Parse certificate subject into structured data
    parseSubject(subject) {
        if (!subject) return {};

        const parsed = {};

        // Split by comma and process each part
        subject.split(',').forEach(part => {
            const [key, ...valueParts] = part.trim().split('=');
            if (key && valueParts.length > 0) {
                const value = valueParts.join('=').trim();
                parsed[key.toLowerCase()] = value;
            }
        });

        return parsed;
    },

    // Get formatted certificate details from subject parsing
    getCertificateDetails(cert) {
        const parsed = this.parseSubject(cert.subject);

        return {
            commonName: parsed.cn || parsed.caption || '',
            surname: parsed.surname || '',
            givenName: parsed.g || '',
            organization: parsed.o || '',
            organizationalUnit: parsed.ou || '',
            bin: this.extractBinFromOU(parsed.ou) || cert.bin,
            businessCategory: parsed.businesscategory || '',
            position: parsed.dc || parsed.g || '',
            country: parsed.c || '',
            email: parsed.e || cert.email || ''
        };
    },

    // Extract BIN from OU string if it contains BIN=
    extractBinFromOU(ou) {
        if (!ou) return null;
        const match = ou.match(/BIN(\d+)/);
        return match ? match[1] : null;
    },

    // Generate initials for pseudo avatar from certificate subject or alias
    generateInitials(cert) {
        const details = this.getCertificateDetails(cert);

        // First try from parsed subject data
        if (details.givenName && details.surname) {
            return (details.givenName[0] + details.surname[0]).toUpperCase();
        }
        if (details.commonName && details.surname) {
            return (details.commonName[0] + details.surname[0]).toUpperCase();
        }

        // Fallback to current logic
        if (cert.subject) {
            const cnMatch = cert.subject.match(/CN=([^,]+)/i);
            if (cnMatch && cnMatch[1]) {
                const name = cnMatch[1].trim();
                const parts = name.split(/\s+/);
                if (parts.length >= 2) {
                    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                } else if (parts.length === 1) {
                    return parts[0].substring(0, 2).toUpperCase();
                }
            }
        }

        // Fallback to alias first two characters
        return cert.alias ? cert.alias.substring(0, 2).toUpperCase() : 'NA';
    },

    // Generate full name from certificate data
    getFullName(cert) {
        const details = this.getCertificateDetails(cert);
        const parts = [];

        if (details.givenName) parts.push(details.givenName);
        if (details.commonName) parts.push(details.commonName);
        //if (details.surname) parts.push(details.surname);

        return parts.length > 0 ? parts.join(' ') : cert.alias;
    },

    // Generate avatar background pattern using certificate properties
    getAvatarPattern(cert) {
        // Create pseudo-random pattern based on alias or serial number
        const seed = cert.alias || cert.serialNumber || cert.subject || 'default';
        const patterns = [
            'bg-gradient-to-br from-blue-400 to-blue-600',
            'bg-gradient-to-br from-green-400 to-green-600',
            'bg-gradient-to-br from-purple-400 to-purple-600',
            'bg-gradient-to-br from-orange-400 to-orange-600',
            'bg-gradient-to-br from-pink-400 to-pink-600',
            'bg-gradient-to-br from-teal-400 to-teal-600',
            'bg-gradient-to-br from-indigo-400 to-indigo-600',
            'bg-gradient-to-br from-red-400 to-red-600'
        ];
        // Simple hash to get consistent pattern
        let hash = 0;
        for (let i = 0; i < seed.length; i++) {
            hash = ((hash << 5) - hash) + seed.charCodeAt(i);
            hash = hash & hash; // Convert to 32-bit integer
        }
        return patterns[Math.abs(hash) % patterns.length];
    },

    formatDate(dateString) {
        return new Date(dateString).toLocaleDateString();
    },

    formatKeyInfo(cert) {
        if (!cert.publicKeyAlgorithm && !cert.keySize) return 'N/A';
        const parts = [];
        if (cert.publicKeyAlgorithm) parts.push(cert.publicKeyAlgorithm);
        if (cert.keySize) parts.push(`${cert.keySize} bits`);
        return parts.join(', ');
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

});
