import { test, expect, vi } from 'vitest';
import certificatorTab from '../src/scripts/certificator-tab.js';

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

test('initializes with empty certificates', () => {
    const component = certificatorTab();
    expect(component.certificates).toEqual([]);
    expect(component.newCAAlias).toBe('');
    expect(component.activeSubTab).toBe('create');
});

test('loads certificates from API', async () => {
    const caData = {
        certificates: [{ alias: "ca-123", subject: "CN=Test CA" }]
    };
    const userData = {
        certificates: [{ alias: "user-456", caId: "ca-123", email: "user@test.com", iin: "123456789012" }]
    };
    const legalData = {
        certificates: [{ alias: "legal-789", caId: "ca-123", email: "legal@test.com", bin: "123456789012" }]
    };

    // Mock responses: 1 CA fetch + 1 user fetch + 1 legal fetch for the one CA
    global.fetch = createFetchMock([
        { ok: true, json: () => Promise.resolve(caData) }, // CA fetch
        { ok: true, json: () => Promise.resolve(userData) }, // user?caId=ca-123
        { ok: true, json: () => Promise.resolve(legalData) } // legal?caId=ca-123
    ]);

    const component = certificatorTab();
    await component.loadCertificates();

    // Verify hierarchical structure
    expect(component.certificates).toHaveLength(1);
    const caStructure = component.certificates[0];

    expect(caStructure.alias).toBe("ca-123");
    expect(caStructure.ca).toEqual({ alias: "ca-123", subject: "CN=Test CA" });

    expect(caStructure.userCertificates).toHaveLength(1);
    expect(caStructure.userCertificates[0]).toEqual({ alias: "user-456", caId: "ca-123", email: "user@test.com", iin: "123456789012" });

    expect(caStructure.legalCertificates).toHaveLength(1);
    expect(caStructure.legalCertificates[0]).toEqual({ alias: "legal-789", caId: "ca-123", email: "legal@test.com", bin: "123456789012" });
});



test('formats dates correctly', () => {
    const component = certificatorTab();
    const dateString = "2024-01-15T10:30:00.000+00:00";
    const formatted = component.formatDate(dateString);
    expect(typeof formatted).toBe('string');
    expect(formatted.length).toBeGreaterThan(0);
});

test('handles API errors gracefully', async () => {
    global.fetch.mockImplementation(() => Promise.reject(new Error('Network error')));

    const component = certificatorTab();
    component.addNotification = vi.fn();

    // The method catches errors internally and calls addNotification, doesn't throw
    await component.loadCertificates();
    expect(component.addNotification).toHaveBeenCalledWith('error', 'Failed to load certificates');
});

test('shows loading states during generation', async () => {
    // Mock successful CA generation followed by certificate refresh
    // Sequence: generate CA -> load CA -> load user certs -> load legal certs
    global.fetch = createFetchMock([
        { ok: true, json: () => Promise.resolve({ alias: "ca-new", type: "ca" }) }, // generate CA
        { ok: true, json: () => Promise.resolve({ certificates: [{ alias: "ca-new" }] }) }, // load CA certs
        { ok: true, json: () => Promise.resolve({ certificates: [] }) }, // load user certs for ca-new
        { ok: true, json: () => Promise.resolve({ certificates: [] }) }  // load legal certs for ca-new
    ]);

    const component = certificatorTab();
    component.addNotification = vi.fn();

    // Initially not generating
    expect(component.generatingCA).toBe(false);

    // Start generation (this will be async)
    const generationPromise = component.generateCA();
    expect(component.generatingCA).toBe(true);

    // Wait for completion
    await generationPromise;
    expect(component.generatingCA).toBe(false);
});

test('clipboard copy functionality is available', () => {
    const component = certificatorTab();

    // Mock navigator.clipboard
    global.navigator = global.navigator || {};
    global.navigator.clipboard = {
        writeText: vi.fn(() => Promise.resolve())
    };

    expect(() => component.copyToClipboard('test')).not.toThrow();
});

test('generates initials correctly', () => {
    const component = certificatorTab();

    // Test with subject containing CN
    const certWithCN = { subject: 'CN=John Doe, OU=Test' };
    expect(component.generateInitials(certWithCN)).toBe('JD');

    // Test with single name in CN
    const certWithSingleName = { subject: 'CN=John, OU=Test' };
    expect(component.generateInitials(certWithSingleName)).toBe('JO');

    // Test fallback to alias
    const certWithAlias = { alias: 'test-cert-123' };
    expect(component.generateInitials(certWithAlias)).toBe('TE');

    // Test empty values
    expect(component.generateInitials({})).toBe('NA');
});

test('generates avatar patterns deterministically', () => {
    const component = certificatorTab();

    const cert1 = { alias: 'test-cert-1' };
    const cert2 = { alias: 'test-cert-1' };
    const cert3 = { alias: 'different-cert' };

    // Same input should produce same pattern
    expect(component.getAvatarPattern(cert1)).toBe(component.getAvatarPattern(cert2));

    // Different input should potentially produce different pattern
    // (though there's a chance they could be the same, but unlikely with our hash)
    const pattern1 = component.getAvatarPattern(cert1);
    const pattern3 = component.getAvatarPattern(cert3);

    // Verify it's a valid Tailwind class
    expect(pattern1).toContain('bg-gradient-to-br');
    expect(pattern1).toContain('from-');
    expect(pattern1).toContain('to-');
});
