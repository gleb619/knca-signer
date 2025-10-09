import { test, expect, vi } from 'vitest';
import xmlVerifierTab from '../src/scripts/xml-verifier-tab.js';

// Mock window.knca.translator
global.window = {
  knca: {
    translator: {
      t: (key) => key // Return key as translation
    }
  }
};

test('xmlVerifierTab initializes with default values', () => {
  const instance = xmlVerifierTab();

  expect(instance.isValidating).toBe(false);
  expect(instance.validationResult).toBe(null);
  expect(instance.validationConfig.checkKalkanProvider).toBe(false);
  expect(instance.validationConfig.checkData).toBe(false);
  expect(instance.validationConfig.checkTime).toBe(false);
  expect(instance.validationConfig.checkIinInCert).toBe(false);
  expect(instance.validationConfig.checkIinInSign).toBe(false);
  expect(instance.validationConfig.checkBinInCert).toBe(false);
  expect(instance.validationConfig.checkBinInSign).toBe(false);
  expect(instance.validationConfig.checkCertificateChain).toBe(false);
  expect(instance.validationConfig.checkPublicKey).toBe(false);
  expect(instance.validationConfig.expectedIin).toBe('');
  expect(instance.validationConfig.expectedBin).toBe('');
  expect(instance.validationConfig.caPem).toBe(undefined);
  expect(instance.xmlContentSample).toContain('<?xml version="1.0"');
  expect(instance.publicKeyFile).toBe(null);
  expect(instance.publicKeyFileName).toBe('');
  expect(instance.caPemFile).toBe(null);
  expect(instance.caPemFileName).toBe('');
});

test('isValidating property controls loading state', () => {
  const instance = xmlVerifierTab();

  expect(instance.isValidating).toBe(false);
  instance.isValidating = true;
  expect(instance.isValidating).toBe(true);
  instance.isValidating = false;
  expect(instance.isValidating).toBe(false);
});

test('resetValidation clears all fields', () => {
  const instance = xmlVerifierTab();

  // Set some values
  instance.xmlContent = 'test xml';
  instance.validationConfig.checkKalkanProvider = true;
  instance.validationConfig.checkData = true;
  instance.validationConfig.checkPublicKey = true;
  instance.validationConfig.expectedIin = '123456789012';
  instance.validationConfig.expectedBin = '123456789012';
  instance.publicKeyFile = { name: 'test.pem' };
  instance.publicKeyFileName = 'test.pem';
  instance.validationConfig.publicKey = 'base64content';
  instance.caPemFile = { name: 'ca.pem' };
  instance.caPemFileName = 'ca.pem';
  instance.validationConfig.caPem = 'caBase64Content';
  instance.validationResult = { valid: true, message: 'test' };
  instance.errorMessage = 'test error';
  instance.successMessage = 'test success';

  // Reset
  instance.resetValidation();

  // Check all cleared
  expect(instance.xmlContent).toBe('');
  expect(instance.validationConfig.checkKalkanProvider).toBe(false);
  expect(instance.validationConfig.checkData).toBe(false);
  expect(instance.validationConfig.checkPublicKey).toBe(false);
  expect(instance.validationConfig.checkBinInCert).toBe(false);
  expect(instance.validationConfig.checkBinInSign).toBe(false);
  expect(instance.validationConfig.expectedIin).toBe('');
  expect(instance.validationConfig.expectedBin).toBe('');
  expect(instance.publicKeyFile).toBe(null);
  expect(instance.publicKeyFileName).toBe('');
  expect(instance.validationConfig.publicKey).toBe('');
  expect(instance.caPemFile).toBe(null);
  expect(instance.caPemFileName).toBe('');
  expect(instance.validationConfig.caPem).toBe('');
  expect(instance.validationResult).toBe(null);
  expect(instance.errorMessage).toBe('');
  expect(instance.successMessage).toBe('');
});

test('validateXml validates public key requirement', () => {
  const instance = xmlVerifierTab();

  instance.xmlContent = '<xml>test</xml>';
  instance.validationConfig.checkPublicKey = true;

  // Should error when public key is required but not provided
  instance.validateXml();

  expect(instance.errorMessage).toBe('publicKeyRequired');
  expect(instance.validationResult).toBe(null);
});

test('copyValidationResult with validation result', () => {
  const instance = xmlVerifierTab();

  // Mock validation result
  instance.validationResult = {
    valid: true,
    message: 'Validation passed',
    details: {
      signatureValid: 'true',
      kalkanProviderUsed: 'false'
    }
  };

  // Mock navigator.clipboard
  const mockClipboard = {
    writeText: vi.fn().mockResolvedValue()
  };
  Object.defineProperty(navigator, 'clipboard', {
    value: mockClipboard,
    writable: true
  });

  instance.copyValidationResult();

  expect(mockClipboard.writeText).toHaveBeenCalledWith(
    'validationResult: valid\nvalidationDetails: Validation passed\n\nvalidationDetails:\nsignatureValid: true\nkalkanProviderUsed: false\n'
  );
});

test('copyValidationResult fallback exists', () => {
  const instance = xmlVerifierTab();

  // Mock validation result
  instance.validationResult = {
    valid: false,
    message: 'Validation failed'
  };

  // Mock navigator.clipboard as undefined (simulating browsers without clipboard API)
  const originalClipboard = navigator.clipboard;
  Object.defineProperty(navigator, 'clipboard', {
    value: undefined,
    writable: true
  });

  // Just check that the fallback code exists and runs without throwing
  expect(() => instance.copyValidationResult()).not.toThrow();

  // Restore original clipboard
  Object.defineProperty(navigator, 'clipboard', {
    value: originalClipboard,
    writable: true
  });
});

test('validation flags are boolean', () => {
  const instance = xmlVerifierTab();

  // Test default values
  expect(typeof instance.validationConfig.checkKalkanProvider).toBe('boolean');
  expect(typeof instance.validationConfig.checkData).toBe('boolean');
  expect(typeof instance.validationConfig.checkTime).toBe('boolean');
  expect(typeof instance.validationConfig.checkIinInCert).toBe('boolean');
  expect(typeof instance.validationConfig.checkIinInSign).toBe('boolean');
  expect(typeof instance.validationConfig.checkBinInCert).toBe('boolean');
  expect(typeof instance.validationConfig.checkBinInSign).toBe('boolean');
  expect(typeof instance.validationConfig.checkCertificateChain).toBe('boolean');
  expect(typeof instance.validationConfig.checkPublicKey).toBe('boolean');

  // Test changing values
  instance.validationConfig.checkKalkanProvider = true;
  instance.validationConfig.checkData = true;
  instance.validationConfig.checkPublicKey = true;
  instance.validationConfig.checkBinInCert = true;
  expect(instance.validationConfig.checkKalkanProvider).toBe(true);
  expect(instance.validationConfig.checkData).toBe(true);
  expect(instance.validationConfig.checkPublicKey).toBe(true);
  expect(instance.validationConfig.checkBinInCert).toBe(true);
});

test('expectedIin and expectedBin are string', () => {
  const instance = xmlVerifierTab();

  expect(typeof instance.validationConfig.expectedIin).toBe('string');
  expect(instance.validationConfig.expectedIin).toBe('');
  expect(typeof instance.validationConfig.expectedBin).toBe('string');
  expect(instance.validationConfig.expectedBin).toBe('');

  instance.validationConfig.expectedIin = '123456789012';
  instance.validationConfig.expectedBin = '123456789012';
  expect(instance.validationConfig.expectedIin).toBe('123456789012');
  expect(instance.validationConfig.expectedBin).toBe('123456789012');
});

test('handlePublicKeyFileChange sets file and processes base64 content', () => {
  const instance = xmlVerifierTab();

  // Mock FileReader
  const mockReader = {
    onload: null,
    readAsDataURL: vi.fn()
  };
  global.FileReader = vi.fn().mockImplementation(() => mockReader);

  // Create mock file
  const mockFile = {
    name: 'test-public-key.pem'
  };
  const mockEvent = {
    target: {
      files: [mockFile]
    }
  };

  // Call function
  instance.handlePublicKeyFileChange(mockEvent);

  // Check initial setup
  expect(instance.publicKeyFileName).toBe('test-public-key.pem');
  expect(instance.publicKeyFile).toBe(mockFile);
  expect(global.FileReader).toHaveBeenCalledTimes(1);
  expect(mockReader.readAsDataURL).toHaveBeenCalledWith(mockFile);

  // Simulate FileReader onload with base64 data
  mockReader.onload({
    target: {
      result: 'data:text/plain;base64,dGVzdCBkYXRh'
    }
  });

  expect(instance.validationConfig.publicKey).toBe('dGVzdCBkYXRh');
});

test('handlePublicKeyFileChange handles no file selected', () => {
  const instance = xmlVerifierTab();

  // Set some initial values
  instance.publicKeyFileName = 'existing.pem';
  instance.publicKeyFile = {};
  instance.validationConfig.publicKey = 'existing';

  const mockEvent = {
    target: {
      files: []
    }
  };

  // Call function
  instance.handlePublicKeyFileChange(mockEvent);

  // Check cleanup
  expect(instance.publicKeyFileName).toBe('');
  expect(instance.publicKeyFile).toBe(null);
  expect(instance.validationConfig.publicKey).toBe('');
});

test('handleCaPemFileChange sets file and processes base64 content', () => {
  const instance = xmlVerifierTab();

  // Mock FileReader
  const mockReader = {
    onload: null,
    readAsDataURL: vi.fn()
  };
  global.FileReader = vi.fn().mockImplementation(() => mockReader);

  // Create mock file
  const mockFile = {
    name: 'test-ca.pem'
  };
  const mockEvent = {
    target: {
      files: [mockFile]
    }
  };

  // Call function
  instance.handleCaPemFileChange(mockEvent);

  // Check initial setup
  expect(instance.caPemFileName).toBe('test-ca.pem');
  expect(instance.caPemFile).toBe(mockFile);
  expect(global.FileReader).toHaveBeenCalledTimes(1);
  expect(mockReader.readAsDataURL).toHaveBeenCalledWith(mockFile);

  // Simulate FileReader onload with base64 data
  mockReader.onload({
    target: {
      result: 'data:text/plain;base64,Y2EgZGF0YQ=='
    }
  });

  expect(instance.validationConfig.caPem).toBe('Y2EgZGF0YQ==');
});

test('handleCaPemFileChange handles no file selected', () => {
  const instance = xmlVerifierTab();

  // Set some initial values
  instance.caPemFileName = 'existing-ca.pem';
  instance.caPemFile = {};
  instance.validationConfig.caPem = 'existing';

  const mockEvent = {
    target: {
      files: []
    }
  };

  // Call function
  instance.handleCaPemFileChange(mockEvent);

  // Check cleanup
  expect(instance.caPemFileName).toBe('');
  expect(instance.caPemFile).toBe(null);
  expect(instance.validationConfig.caPem).toBe('');
});
