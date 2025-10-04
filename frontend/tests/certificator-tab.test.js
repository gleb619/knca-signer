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

    // Mock responses: 1 CA fetch + 1 user fetch + 1 legal fetch for the one CA
    global.fetch = createFetchMock([
        { json: () => Promise.resolve(caResponse) }, // CA fetch
        { json: () => Promise.resolve(userResponse) }, // user?caId=ca-123
        { json: () => Promise.resolve(legalResponse) } // legal?caId=ca-123
    ]);

    const component = certificatorTab();
    await component.loadCertificates();

    expect(component.certificates.ca).toEqual(caResponse);
    expect(component.certificates.user).toEqual(userResponse);
    expect(component.certificates.legal).toEqual(legalResponse);
});

test('filters users by CA correctly', () => {
    const component = certificatorTab();
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
    const component = certificatorTab();
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
    const component = certificatorTab();
    component.expandedCAs = { "ca-123": false, "ca-456": true };

    component.toggleCAExpansion("ca-123");
    expect(component.expandedCAs["ca-123"]).toBe(true);

    component.toggleCAExpansion("ca-123");
    expect(component.expandedCAs["ca-123"]).toBe(false);

    expect(component.expandedCAs["ca-456"]).toBe(true); // unchanged
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

    // The method catches errors internally and sets errorMessage, doesn't throw
    await component.loadCertificates();
    expect(component.errorMessage).toBe('Failed to load certificates');
});

test('shows loading states during generation', async () => {
    // Mock successful CA generation followed by certificate refresh
    // Sequence: generate CA -> load CA -> load user certs -> load legal certs
    global.fetch = createFetchMock([
        { ok: true, json: () => Promise.resolve({ alias: "ca-new", type: "ca" }) }, // generate CA
        { json: () => Promise.resolve({ "ca-new": { alias: "ca-new" } }) }, // load CA certs
        { json: () => Promise.resolve({}) }, // load user certs for ca-new
        { json: () => Promise.resolve({}) }  // load legal certs for ca-new
    ]);

    const component = certificatorTab();

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
