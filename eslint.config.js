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
    },
  },
];
