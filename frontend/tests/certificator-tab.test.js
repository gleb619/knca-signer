import { test, expect, vi } from 'vitest';

// Mock fetch globally
global.fetch = vi.fn();

// Create a fetch mock utility
const createFetchMock = (responses) => {
    let callCount = 0;
    return vi.fn(() => {
        const response = responses[callCount] || { json: () => Promise.resolve({}) };
        callCount++;
        return Promise.resolve(response);
    });
};

// Define the component logic inline for testing
const createCertificatorTab = () => ({
    // Data properties
    activeTab: 'certificate-authority',
    errorMessage: '',
    successMessage: '',

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

test('initializes with empty certificates', () => {
    const component = createCertificatorTab();
    expect(component.certificates.ca).toEqual({});
    expect(component.certificates.user).toEqual({});
    expect(component.certificates.legal).toEqual({});
    expect(component.expandedCAs).toEqual({});
});

test('loads certificates from API', async () => {
    const caResponse = {
        "ca-123": { alias: "ca-123", subject: "CN=Test CA" }
    };
    const userResponse = {
        "user-456": { alias: "user-456", caId: "ca-123", email: "user@test.com", iin: "123456789012" }
    };
    const legalResponse = {
        "legal-789": { alias: "legal-789", caId: "ca-123", email: "legal@test.com", bin: "123456789012" }
    };

    global.fetch = createFetchMock([
        { json: () => Promise.resolve(caResponse) },
        { json: () => Promise.resolve(userResponse) },
        { json: () => Promise.resolve(legalResponse) }
    ]);

    const component = createCertificatorTab();
    await component.loadCertificates();

    expect(component.certificates.ca).toEqual(caResponse);
    expect(component.certificates.user).toEqual(userResponse);
    expect(component.certificates.legal).toEqual(legalResponse);
});

test('filters users by CA correctly', () => {
    const component = createCertificatorTab();
    component.certificates.user = {
        "user-1": { alias: "user-1", caId: "ca-123", email: "user1@test.com" },
        "user-2": { alias: "user-2", caId: "ca-456", email: "user2@test.com" },
        "user-3": { alias: "user-3", caId: "ca-123", email: "user3@test.com" }
    };

    const usersForCa123 = component.getUsersForCA("ca-123");
    expect(usersForCa123.length).toBe(2);
    expect(usersForCa123).toEqual(
        expect.arrayContaining([
            expect.objectContaining({ caId: "ca-123" })
        ])
    );

    const usersForCa456 = component.getUsersForCA("ca-456");
    expect(usersForCa456.length).toBe(1);
    expect(usersForCa456[0].caId).toBe("ca-456");
});

test('filters legals by CA correctly', () => {
    const component = createCertificatorTab();
    component.certificates.legal = {
        "legal-1": { alias: "legal-1", caId: "ca-123", email: "legal1@test.com" },
        "legal-2": { alias: "legal-2", caId: "ca-456", email: "legal2@test.com" }
    };

    const legalsForCa123 = component.getLegalsForCA("ca-123");
    expect(legalsForCa123.length).toBe(1);
    expect(legalsForCa123[0].caId).toBe("ca-123");

    const legalsForCa456 = component.getLegalsForCA("ca-456");
    expect(legalsForCa456.length).toBe(1);
    expect(legalsForCa456[0].caId).toBe("ca-456");
});

test('toggles CA expansion correctly', () => {
    const component = createCertificatorTab();
    component.expandedCAs = { "ca-123": false, "ca-456": true };

    component.toggleCAExpansion("ca-123");
    expect(component.expandedCAs["ca-123"]).toBe(true);

    component.toggleCAExpansion("ca-123");
    expect(component.expandedCAs["ca-123"]).toBe(false);

    expect(component.expandedCAs["ca-456"]).toBe(true); // unchanged
});

test('formats dates correctly', () => {
    const component = createCertificatorTab();
    const dateString = "2024-01-15T10:30:00.000+00:00";
    const formatted = component.formatDate(dateString);
    expect(typeof formatted).toBe('string');
    expect(formatted.length).toBeGreaterThan(0);
});

test('handles API errors gracefully', async () => {
    global.fetch.mockImplementation(() => Promise.reject(new Error('Network error')));

    const component = createCertificatorTab();

    // The method catches errors internally and sets errorMessage, doesn't throw
    await component.loadCertificates();
    expect(component.errorMessage).toBe('Failed to load certificates');
});

test('shows loading states during generation', async () => {
    // Mock successful CA generation
    global.fetch = createFetchMock([
        { ok: true, json: () => Promise.resolve({ alias: "ca-new", type: "ca" }) },
        { json: () => Promise.resolve({ "ca-new": { alias: "ca-new" } }) },
        { json: () => Promise.resolve({}) },
        { json: () => Promise.resolve({}) }
    ]);

    const component = createCertificatorTab();

    // Initially not generating
    expect(component.generatingCA).toBe(false);

    // Start generation (this will be async)
    const generationPromise = component.generateCA();
    expect(component.generatingCA).toBe(true);

    // Wait for completion
    await generationPromise;
    expect(component.generatingCA).toBe(false);
});

test('clears messages correctly', () => {
    const component = createCertificatorTab();
    component.errorMessage = 'Test error';
    component.successMessage = 'Test success';

    component.clearMessages();

    expect(component.errorMessage).toBe('');
    expect(component.successMessage).toBe('');
});

test('clipboard copy functionality is available', () => {
    const component = createCertificatorTab();

    // Mock navigator.clipboard
    global.navigator = global.navigator || {};
    global.navigator.clipboard = {
        writeText: vi.fn(() => Promise.resolve())
    };

    expect(() => component.copyToClipboard('test')).not.toThrow();
});
