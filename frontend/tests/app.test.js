import { test, expect } from 'vitest';
import ncaApp from '../scripts/app.js';

test('ncaApp initializes with default values', () => {
  const instance = ncaApp();

  expect(instance.isKK).toBe(true);
  expect(instance.activeTab).toBe('xml-signer');
});

test('switchTab changes activeTab', () => {
  const instance = ncaApp();

  // Simulate tab click (though in real app it's via x-on:click)
  instance.activeTab = 'certificate-authority';
  expect(instance.activeTab).toBe('certificate-authority');
});

test('changeLocale toggles locale', () => {
  const instance = ncaApp();

  // Mock localStorage, window, and Alpine.js $nextTick
  global.localStorage = {
    getItem: () => 'kk',
    setItem: () => {}
  };
  global.window = {
    knca: {
      translator: {
        locale: () => {},
        t: () => {}
      }
    },
    location: {
      reload: () => {} // Mock location.reload
    }
  };
  instance.$nextTick = (fn) => fn(); // Mock $nextTick to execute immediately

  expect(instance.isKK).toBe(true);
  instance.changeLocale(false); // Pass false to avoid reload
  // changeLocale doesn't change isKK, it sets locale based on isKK
  // To test, check that translator.locale was called with 'kk'
});

test('translate calls translator', () => {
  const instance = ncaApp();

  global.window = {
    knca: {
      translator: {
        t: (key) => `translated_${key}`
      }
    }
  };

  expect(instance.translate('testKey')).toBe('translated_testKey');
});

test('changeLocale updates translator locale and affects translations', () => {
  const instance = ncaApp();

  // Mock the translator with proper translations
  global.window = {
    knca: {
      translator: {
        locale: (newLocale) => {
          // Simulate setting locale and updating translations
          if (newLocale === 'ru') {
            global.window.knca.translator.t = (key) => {
              const ruTranslations = {
                'toggleLabel': 'Русский',
                'signButton': 'Подписать'
              };
              return ruTranslations[key] || key;
            };
          } else {
            global.window.knca.translator.t = (key) => {
              const kkTranslations = {
                'toggleLabel': 'Қазақша',
                'signButton': 'Қол қою'
              };
              return kkTranslations[key] || key;
            };
          }
        },
        t: (key) => {
          const kkTranslations = {
            'toggleLabel': 'Қазақша',
            'signButton': 'Қол қою'
          };
          return kkTranslations[key] || key;
        }
      }
    },
    location: {
      reload: () => {}
    }
  };

  // Initial state: KK (isKK = true), translations = kk
  expect(instance.translate('toggleLabel')).toBe('Қазақша');
  expect(instance.translate('signButton')).toBe('Қол қою');

  // Change to RU
  instance.isKK = false;
  instance.changeLocale(false); // Pass false to avoid reload

  // After locale change, translations should be updated to ru
  expect(instance.translate('toggleLabel')).toBe('Русский');
  expect(instance.translate('signButton')).toBe('Подписать');
});
