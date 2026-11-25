module.exports = [
  {
    files: ['static/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
    },
    rules: {
      'no-unused-vars': ['error', {
        args: 'after-used',
        caughtErrors: 'all',
      }],
      eqeqeq: ['error', 'smart'],
      'prefer-const': ['error', { ignoreReadBeforeAssign: true }],
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unused-expressions': 'error',
      'no-var': 'error',
      'no-redeclare': 'error',
      'no-dupe-keys': 'error',
    },
  },
];
