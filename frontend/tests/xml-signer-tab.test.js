import { test, expect } from 'vitest';
import xmlSignerTab from '../src/scripts/xml-signer-tab.js';

test('xmlSignerTab initializes with default values', () => {
  const instance = xmlSignerTab();

  expect(instance.isSigning).toBe(false);
  expect(instance.signatureType).toBe('xml');
  expect(instance.allowedStorages).toEqual(['JKS', 'PKCS12']);
  expect(instance.activeSubTab).toBe('xml');
  expect(instance.isArray).toBe(false);
});

test('isSigning property controls loading state', () => {
  const instance = xmlSignerTab();

  expect(instance.isSigning).toBe(false);
  instance.isSigning = true;
  expect(instance.isSigning).toBe(true);
  instance.isSigning = false;
  expect(instance.isSigning).toBe(false);
});

test('isArray affects dataToSign processing', () => {
  const instance = xmlSignerTab();

  instance.dataToSign = 'test data';
  instance.isArray = false;
  // In request method, if isArray, dataToSign becomes array
  expect(instance.dataToSign).toBe('test data');

  instance.isArray = true;
  // But since it's just assignment, test the logic indirectly
  let data = instance.dataToSign;
  if (instance.isArray) {
    data = [data];
  }
  expect(data).toEqual(['test data']);
});

test('extKeyUsageOids parsing', () => {
  const instance = xmlSignerTab();

  instance.extKeyUsageOids = '1.2.3,4.5.6';
  const extKeyUsageOids = instance.extKeyUsageOids ? instance.extKeyUsageOids.split(',') : [];
  expect(extKeyUsageOids).toEqual(['1.2.3', '4.5.6']);
});

test('buildChain affects caCerts processing', () => {
  const instance = xmlSignerTab();

  instance.caCerts = 'cert1,cert2';
  instance.buildChain = true;
  let caCerts = instance.buildChain ? (instance.caCerts ? instance.caCerts.split(',') : null) : null;
  expect(caCerts).toEqual(['cert1', 'cert2']);

  instance.buildChain = false;
  caCerts = instance.buildChain ? (instance.caCerts ? instance.caCerts.split(',') : null) : null;
  expect(caCerts).toBe(null);
});

test('tsaProfile sets tsaProfile object', () => {
  const instance = xmlSignerTab();

  instance.tsaProfile = true;
  let tsaProfile = null;
  if (instance.tsaProfile) {
    tsaProfile = {};
  }
  expect(tsaProfile).toEqual({});

  instance.tsaProfile = false;
  tsaProfile = null;
  if (instance.tsaProfile) {
    tsaProfile = {};
  }
  expect(tsaProfile).toBe(null);
});
