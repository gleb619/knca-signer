// API functions for certificate management - pure functions handling network operations only

export async function fetchCACertificates() {
    const response = await fetch('/api/certificates/ca');
    if (!response.ok) {
        throw new Error(`Failed to fetch CA certificates: ${response.statusText}`);
    }
    const data = await response.json();
    return data.certificates || [];
}

export async function fetchUserCertificates(caId) {
    const response = await fetch(`/api/certificates/user?caId=${caId}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch user certificates for CA ${caId}: ${response.statusText}`);
    }
    const data = await response.json();
    return data.certificates || [];
}

export async function fetchLegalCertificates(caId) {
    const response = await fetch(`/api/certificates/legal?caId=${caId}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch legal certificates for CA ${caId}: ${response.statusText}`);
    }
    const data = await response.json();
    return data.certificates || [];
}

export async function loadCertificates() {
    try {
        // First, load CA certificates
        const caCertificates = await fetchCACertificates();

        // Build hierarchical structure: array of CA objects with nested user/legal certificates
        const certificates = [];

        for (const caCert of caCertificates) {
            // Create CA structure with its certificates
            const caStructure = {
                ca: caCert,
                userCertificates: [],
                legalCertificates: [],
                alias: caCert.alias // convenience property
            };

            // Load user certificates for this CA
            try {
                caStructure.userCertificates = await fetchUserCertificates(caCert.alias);
            } catch (e) {
                console.warn(`Failed to load user certificates for CA ${caCert.alias}:`, e);
            }

            // Load legal certificates for this CA
            try {
                caStructure.legalCertificates = await fetchLegalCertificates(caCert.alias);
            } catch (e) {
                console.warn(`Failed to load legal certificates for CA ${caCert.alias}:`, e);
            }

            certificates.push(caStructure);
        }

        return certificates;

    } catch (error) {
        console.error('Failed to load certificates:', error);
        throw error;
    }
}

export async function generateCACertificate(alias = '') {
    // Build URL with optional alias parameter
    const url = alias.trim()
        ? `/api/certificates/generate/ca?alias=${encodeURIComponent(alias.trim())}`
        : '/api/certificates/generate/ca';

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();
    return result;
}

export async function generateUserCertificate(caId) {
    const response = await fetch('/api/certificates/generate/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ caId })
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();
    return result;
}

export async function generateLegalCertificate(caId) {
    const response = await fetch('/api/certificates/generate/legal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ caId })
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();
    return result;
}

export async function downloadCertificate(alias, format) {
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

    return filename;
}
