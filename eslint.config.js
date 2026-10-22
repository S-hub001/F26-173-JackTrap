// Lint keeps one job: catch typos and names that don't exist.
const globals = require('globals');

module.exports = [
  { ignores: ['node_modules/**', 'test-pages/**'] },
  {
    files: ['extension/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.browser, ...globals.webextensions, ...globals.serviceworker, module: 'writable' }
    },
    rules: { 'no-undef': 'error' }
  },
  {
    files: ['tests/**/*.js', 'eslint.config.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: { ...globals.node, ...globals.jest, ...globals.browser }
    },
    rules: { 'no-undef': 'error' }
  }
];
