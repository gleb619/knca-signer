import { test, expect, vi, beforeEach, afterEach, describe } from 'vitest';
import appStore from '../src/scripts/app-store.js';

// Mock localStorage
const localStorageMock = {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn()
};
Object.defineProperty(window, 'localStorage', {
    value: localStorageMock
});

// Mock fetch
global.fetch = vi.fn();

// Mock window.dispatchEvent
const dispatchEventMock = vi.fn();
window.dispatchEvent = dispatchEventMock;

// Mock console methods
const consoleInfoMock = vi.fn();
const consoleWarnMock = vi.fn();
console.info = consoleInfoMock;
console.warn = consoleWarnMock;

describe('appStore', () => {
    beforeEach(() => {
        // Reset store state
        appStore.selectedUserCert = null;
        appStore.selectedLegalCert = null;
        appStore.selectedCaCert = null;
        appStore.certCache = {};

        // Reset mocks
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('initial state', () => {
        test('should have null initial certificate selections', () => {
            expect(appStore.selectedUserCert).toBeNull();
            expect(appStore.selectedLegalCert).toBeNull();
            expect(appStore.selectedCaCert).toBeNull();
        });

        test('should have empty certificate cache', () => {
            expect(appStore.certCache).toEqual({});
        });
    });

    describe('saveToStorage', () => {
        test('should save certificate data to localStorage', () => {
            const mockUserCert = { alias: 'user-cert', iin: '123456789012' };
            const mockLegalCert = { alias: 'legal-cert', bin: '987654321098' };
            const mockCaCert = { alias: 'ca-cert' };

            appStore.selectedUserCert = mockUserCert;
            appStore.selectedLegalCert = mockLegalCert;
            appStore.selectedCaCert = mockCaCert;

            // Mock Date.now()
            const mockTimestamp = 1234567890123;
            vi.spyOn(Date, 'now').mockReturnValue(mockTimestamp);

            appStore.saveToStorage();

            expect(localStorageMock.setItem).toHaveBeenCalledWith(
                'knca_selected_certificates',
                JSON.stringify({
                    selectedUserCert: mockUserCert,
                    selectedLegalCert: mockLegalCert,
                    selectedCaCert: mockCaCert,
                    timestamp: mockTimestamp
                })
            );
        });
    });

    describe('loadFromStorage', () => {
        test('should load certificate data from localStorage and emit event', async () => {
            const storedData = {
                selectedUserCert: { alias: 'user-cert' },
                selectedLegalCert: null,
                selectedCaCert: { alias: 'ca-cert' },
                timestamp: Date.now()
            };

            localStorageMock.getItem.mockReturnValue(JSON.stringify(storedData));

            // Mock fetchCaCert to resolve
            const mockPem = '-----BEGIN CERTIFICATE-----\nCA_CERT\n-----END CERTIFICATE-----';
            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            const result = await appStore.loadFromStorage();

            expect(result).toBe(true);
            expect(appStore.selectedUserCert).toEqual(storedData.selectedUserCert);
            expect(appStore.selectedLegalCert).toBeNull();
            expect(appStore.selectedCaCert).toEqual(storedData.selectedCaCert);
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate-selected',
                    detail: expect.objectContaining({
                        userCert: storedData.selectedUserCert,
                        legalCert: null,
                        caCert: storedData.selectedCaCert
                    })
                })
            );
            expect(consoleInfoMock).toHaveBeenCalledWith("Loading state from storage");
        });

        test('should return false when no data in localStorage', async () => {
            localStorageMock.getItem.mockReturnValue(null);

            const result = await appStore.loadFromStorage();

            expect(result).toBe(false);
            expect(appStore.selectedUserCert).toBeNull();
            expect(appStore.selectedLegalCert).toBeNull();
            expect(appStore.selectedCaCert).toBeNull();
        });

        test('should handle invalid JSON in localStorage', async () => {
            localStorageMock.getItem.mockReturnValue('invalid json');

            const result = await appStore.loadFromStorage();

            expect(result).toBe(false);
            expect(consoleWarnMock).toHaveBeenCalledWith('Failed to load certificate selection from localStorage:', expect.any(SyntaxError));
        });
    });

    describe('selectUserCertificate', () => {
        test('should select user certificate and clear legal certificate', () => {
            const mockUserCert = { alias: 'user-cert', iin: '123456789012' };
            const mockLegalCert = { alias: 'legal-cert', bin: '987654321098' };

            // Pre-set legal cert
            appStore.selectedLegalCert = mockLegalCert;

            appStore.selectUserCertificate(mockUserCert);

            expect(appStore.selectedUserCert).toEqual(mockUserCert);
            expect(appStore.selectedLegalCert).toBeNull();
            expect(localStorageMock.setItem).toHaveBeenCalled();
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate-selected',
                    detail: expect.objectContaining({
                        userCert: mockUserCert,
                        legalCert: null,
                        caCert: null
                    })
                })
            );
        });
    });

    describe('selectLegalCertificate', () => {
        test('should select legal certificate and clear user certificate', () => {
            const mockUserCert = { alias: 'user-cert', iin: '123456789012' };
            const mockLegalCert = { alias: 'legal-cert', bin: '987654321098' };

            // Pre-set user cert
            appStore.selectedUserCert = mockUserCert;

            appStore.selectLegalCertificate(mockLegalCert);

            expect(appStore.selectedLegalCert).toEqual(mockLegalCert);
            expect(appStore.selectedUserCert).toBeNull();
            expect(localStorageMock.setItem).toHaveBeenCalled();
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate-selected',
                    detail: expect.objectContaining({
                        userCert: null,
                        legalCert: mockLegalCert,
                        caCert: null
                    })
                })
            );
        });
    });

    describe('selectCaCertificate', () => {
        test('should select CA certificate and fetch CA cert', async () => {
            const mockCaCert = { alias: 'ca-cert' };
            const mockPem = '-----BEGIN CERTIFICATE-----\nCA_CERT\n-----END CERTIFICATE-----';

            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            appStore.selectCaCertificate(mockCaCert);

            expect(appStore.selectedCaCert).toEqual(mockCaCert);
            expect(localStorageMock.setItem).toHaveBeenCalled();

            // Wait for async fetchCaCert
            await new Promise(resolve => setTimeout(resolve, 0));

            expect(global.fetch).toHaveBeenCalledWith('/api/certificates/download/ca-cert/pem');
            expect(appStore.certCache['ca-cert']).toBe(mockPem);
        });
    });

    describe('clearUserSelection', () => {
        test('should clear user certificate selection', () => {
            appStore.selectedUserCert = { alias: 'user-cert' };

            appStore.clearUserSelection();

            expect(appStore.selectedUserCert).toBeNull();
            expect(localStorageMock.setItem).toHaveBeenCalled();
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate:cleared'
                })
            );
        });
    });

    describe('clearLegalSelection', () => {
        test('should clear legal certificate selection', () => {
            appStore.selectedLegalCert = { alias: 'legal-cert' };

            appStore.clearLegalSelection();

            expect(appStore.selectedLegalCert).toBeNull();
            expect(localStorageMock.setItem).toHaveBeenCalled();
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate:cleared'
                })
            );
        });
    });

    describe('clearSelection', () => {
        test('should clear all certificate selections and remove from storage', () => {
            appStore.selectedUserCert = { alias: 'user-cert' };
            appStore.selectedLegalCert = { alias: 'legal-cert' };
            appStore.selectedCaCert = { alias: 'ca-cert' };

            appStore.clearSelection();

            expect(appStore.selectedUserCert).toBeNull();
            expect(appStore.selectedLegalCert).toBeNull();
            expect(appStore.selectedCaCert).toBeNull();
            expect(localStorageMock.removeItem).toHaveBeenCalledWith('knca_selected_certificates');
            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'certificate:cleared'
                })
            );
        });
    });

    describe('emitEvent', () => {
        test('should emit custom event with certificate details', () => {
            const mockUserCert = { alias: 'user-cert' };
            const mockLegalCert = { alias: 'legal-cert' };
            const mockCaCert = { alias: 'ca-cert' };

            appStore.selectedUserCert = mockUserCert;
            appStore.selectedLegalCert = mockLegalCert;
            appStore.selectedCaCert = mockCaCert;

            appStore.emitEvent('test-event');

            expect(dispatchEventMock).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'test-event',
                    detail: {
                        userCert: mockUserCert,
                        legalCert: mockLegalCert,
                        caCert: mockCaCert
                    }
                })
            );
        });
    });

    describe('fetchCaCert', () => {
        test('should return null when no CA certificate selected', async () => {
            appStore.selectedCaCert = null;

            const result = await appStore.fetchCaCert();

            expect(result).toBeNull();
            expect(global.fetch).not.toHaveBeenCalled();
        });

        test('should return cached CA certificate', async () => {
            const mockCaCert = { alias: 'ca-cert' };
            const cachedPem = '-----BEGIN CERTIFICATE-----\nCACHED_CA\n-----END CERTIFICATE-----';

            appStore.selectedCaCert = mockCaCert;
            appStore.certCache['ca-cert'] = cachedPem;

            const result = await appStore.fetchCaCert();

            expect(result).toBe(cachedPem);
            expect(global.fetch).not.toHaveBeenCalled();
        });

        test('should fetch and cache CA certificate', async () => {
            const mockCaCert = { alias: 'ca-cert' };
            const mockPem = '-----BEGIN CERTIFICATE-----\nNEW_CA_CERT\n-----END CERTIFICATE-----';

            appStore.selectedCaCert = mockCaCert;
            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            const result = await appStore.fetchCaCert();

            expect(result).toBe(mockPem);
            expect(global.fetch).toHaveBeenCalledWith('/api/certificates/download/ca-cert/pem');
            expect(appStore.certCache['ca-cert']).toBe(mockPem);
        });

        test('should handle fetch failure for CA certificate', async () => {
            const mockCaCert = { alias: 'ca-cert' };

            appStore.selectedCaCert = mockCaCert;
            global.fetch.mockRejectedValueOnce(new Error('Network error'));

            const result = await appStore.fetchCaCert();

            expect(result).toBeNull();
            expect(consoleWarnMock).toHaveBeenCalledWith('Failed to fetch CA certificate:', expect.any(Error));
        });

        test('should handle non-ok response for CA certificate', async () => {
            const mockCaCert = { alias: 'ca-cert' };

            appStore.selectedCaCert = mockCaCert;
            global.fetch.mockResolvedValueOnce({
                ok: false,
                text: () => Promise.resolve('error')
            });

            const result = await appStore.fetchCaCert();

            expect(result).toBeNull();
        });
    });

    describe('fetchUserCert', () => {
        test('should return null when no user or legal certificate selected', async () => {
            appStore.selectedUserCert = null;
            appStore.selectedLegalCert = null;

            const result = await appStore.fetchUserCert();

            expect(result).toBeNull();
            expect(global.fetch).not.toHaveBeenCalled();
        });

        test('should prioritize user certificate over legal certificate', async () => {
            const mockUserCert = { alias: 'user-cert' };
            const mockLegalCert = { alias: 'legal-cert' };
            const mockPem = '-----BEGIN CERTIFICATE-----\nUSER_CERT\n-----END CERTIFICATE-----';

            appStore.selectedUserCert = mockUserCert;
            appStore.selectedLegalCert = mockLegalCert;
            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            const result = await appStore.fetchUserCert();

            expect(result).toBe(mockPem);
            expect(global.fetch).toHaveBeenCalledWith('/api/certificates/download/user-cert/pem');
        });

        test('should use legal certificate when no user certificate selected', async () => {
            const mockLegalCert = { alias: 'legal-cert' };
            const mockPem = '-----BEGIN CERTIFICATE-----\nLEGAL_CERT\n-----END CERTIFICATE-----';

            appStore.selectedUserCert = null;
            appStore.selectedLegalCert = mockLegalCert;
            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            const result = await appStore.fetchUserCert();

            expect(result).toBe(mockPem);
            expect(global.fetch).toHaveBeenCalledWith('/api/certificates/download/legal-cert/pem');
        });

        test('should return cached user certificate', async () => {
            const mockUserCert = { alias: 'user-cert' };
            const cachedPem = '-----BEGIN CERTIFICATE-----\nCACHED_USER\n-----END CERTIFICATE-----';

            appStore.selectedUserCert = mockUserCert;
            appStore.certCache['user-cert'] = cachedPem;

            const result = await appStore.fetchUserCert();

            expect(result).toBe(cachedPem);
            expect(global.fetch).not.toHaveBeenCalled();
        });

        test('should fetch and cache user certificate', async () => {
            const mockUserCert = { alias: 'user-cert' };
            const mockPem = '-----BEGIN CERTIFICATE-----\nNEW_USER_CERT\n-----END CERTIFICATE-----';

            appStore.selectedUserCert = mockUserCert;
            global.fetch.mockResolvedValueOnce({
                ok: true,
                text: () => Promise.resolve(mockPem)
            });

            const result = await appStore.fetchUserCert();

            expect(result).toBe(mockPem);
            expect(global.fetch).toHaveBeenCalledWith('/api/certificates/download/user-cert/pem');
            expect(appStore.certCache['user-cert']).toBe(mockPem);
        });

        test('should handle fetch failure for user certificate', async () => {
            const mockUserCert = { alias: 'user-cert' };

            appStore.selectedUserCert = mockUserCert;
            global.fetch.mockRejectedValueOnce(new Error('Network error'));

            const result = await appStore.fetchUserCert();

            expect(result).toBeNull();
            expect(consoleWarnMock).toHaveBeenCalledWith('Failed to fetch user certificate:', expect.any(Error));
        });

        test('should handle non-ok response for user certificate', async () => {
            const mockUserCert = { alias: 'user-cert' };

            appStore.selectedUserCert = mockUserCert;
            global.fetch.mockResolvedValueOnce({
                ok: false,
                text: () => Promise.resolve('error')
            });

            const result = await appStore.fetchUserCert();

            expect(result).toBeNull();
        });
    });
});
