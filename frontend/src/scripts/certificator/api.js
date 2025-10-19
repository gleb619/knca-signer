// API functions for certificate management

export async function loadCertificates() {
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

        if(this.certificates.length > 0) {
            this.activeSubTab = this.certificates[0].alias;
        }

    } catch (error) {
        this.certificates = [];
        this.addNotification('error', 'Failed to load certificates');
    }
}

export async function generateCA() {
    this.generatingCA = true;

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

        this.addNotification('success', `CA certificate generated successfully: ${result.alias}`);

        // Clear the input field
        this.newCAAlias = '';

    } catch (error) {
        console.error('Failed to generate CA:', error);
        this.addNotification('error', 'Failed to generate CA certificate');
    } finally {
        this.generatingCA = false;
    }
}

// Common certificate generation pattern
export async function generateCertificate(type, url, body = null) {
    const loadingFlag = `generating${type.charAt(0).toUpperCase() + type.slice(1)}`;

    this[loadingFlag] = true;

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

        this.addNotification('success', `${type === 'CA' ? 'CA' : type.charAt(0).toUpperCase() + type.slice(1).toLowerCase()} certificate generated successfully: ${result.alias}`);

        return result;

    } catch (error) {
        console.error(`Failed to generate ${type.toLowerCase()} certificate:`, error);
        this.addNotification('error', `Failed to generate ${type.toLowerCase()} certificate`);

        throw error;
    } finally {
        this[loadingFlag] = false;
    }
}

export async function downloadCertificate(alias, format) {
    try {
        const url = `/api/certificates/download/${encodeURIComponent(alias)}/${encodeURIComponent(format)}`;
        const response = await fetch(url);

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('Certificate not found');
            }
            throw new Error(`Failed to download certificate: ${response.statusText}`);
        }

        // Get the filename from the Content-Disposition header
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `certificate.${format}`;
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="([^"]*)"/);
            if (filenameMatch) {
                filename = filenameMatch[1];
            }
        }

        // Create blob from response
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);

        // Create temporary link and trigger download
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        // Clean up the URL
        window.URL.revokeObjectURL(downloadUrl);

        this.addNotification('success', `Certificate downloaded successfully: ${filename}`);

    } catch (error) {
        console.error('Download failed:', error);
        this.addNotification('error', `Download failed: ${error.message}`);
    }
}
