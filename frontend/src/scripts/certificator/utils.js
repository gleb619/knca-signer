// UI utility and formatting functions

// Generate initials for pseudo avatar from certificate subject or alias
export function generateInitials(cert) {
    const details = getCertificateDetails(cert);

    // First try from parsed subject data
    if (details.commonName) {
        const name = details.commonName.trim();
        const parts = name.split(/\s+/);
        if (parts.length >= 2) {
            return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        } else {
            return name.substring(0, 2).toUpperCase();
        }
    }

    // Second try from parsed subject data
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
}

// Generate full name from certificate data
export function getFullName(cert) {
    const details = getCertificateDetails(cert);
    const parts = [];

    if (details.givenName) parts.push(details.givenName);
    if (details.commonName) parts.push(details.commonName);
    //if (details.surname) parts.push(details.surname);

    return parts.length > 0 ? parts.join(' ') : cert.alias;
}

// Generate avatar background pattern using certificate properties
export function getAvatarPattern(cert) {
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
}

export function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

export function formatKeyInfo(cert) {
    if (!cert.publicKeyAlgorithm && !cert.keySize) return 'N/A';
    const parts = [];
    if (cert.publicKeyAlgorithm) parts.push(cert.publicKeyAlgorithm);
    if (cert.keySize) parts.push(`${cert.keySize} bits`);
    return parts.join(', ');
}

export function copyToClipboard(text) {
    return new Promise((resolve, reject) => {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                resolve();
            }).catch(() => {
                fallbackCopyToClipboard(text).then(resolve).catch(reject);
            });
        } else {
            fallbackCopyToClipboard(text).then(resolve).catch(reject);
        }
    });
}

export function fallbackCopyToClipboard(text) {
    return new Promise((resolve, reject) => {
        // Check if we have a DOM environment
        if (typeof document === 'undefined') {
            reject(new Error('DOM not available'));
            return;
        }

        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            if (document.execCommand) {
                document.execCommand('copy');
            }
            resolve();
        } catch (err) {
            resolve();
        } finally {
            document.body.removeChild(textArea);
        }
    });
}

// Build hierarchical structure from flat certificates
export function buildHierarchicalFromFlat(flatCertificates) {
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
}

// Parse certificate subject into structured data
export function parseSubject(subject) {
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
}

// Get formatted certificate details from subject parsing
export function getCertificateDetails(cert) {
    const parsed = parseSubject(cert.subject);

    return {
        commonName: parsed.cn || parsed.caption || '',
        surname: parsed.surname || '',
        givenName: parsed.g || '',
        organization: parsed.o || '',
        organizationalUnit: parsed.ou || '',
        bin: extractBinFromOU(parsed.ou) || cert.bin,
        businessCategory: parsed.businesscategory || '',
        position: parsed.dc || parsed.g || '',
        country: parsed.c || '',
        email: parsed.e || cert.email || ''
    };
}

// Extract BIN from OU string if it contains BIN=
export function extractBinFromOU(ou) {
    if (!ou) return null;
    const match = ou.match(/BIN(\d+)/);
    return match ? match[1] : null;
}
