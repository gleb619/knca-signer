import js from '@eslint/js';
import globals from 'globals';

export default [
  js.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
        Alpine: 'readonly',
        htmx: 'readonly'
      },
      ecmaVersion: 2022,
      sourceType: 'module'
    },
    rules: {
      // Add any custom rules here
      'no-unused-vars': 'warn',
      'no-console': 'off'
    }
  },
  {
    ignores: [
      'dist/',
      'node_modules/',
      'coverage/',
      '*.config.js'
    ]
  }
];
