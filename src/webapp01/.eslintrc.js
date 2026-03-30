module.exports = {
  env: {
    browser: true,
    es2021: true,
    jquery: true
  },
  extends: 'eslint:recommended',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'script'
  },
  rules: {
    // Security rules
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    
    // Best practices
    'eqeqeq': ['error', 'always'],
    'no-var': 'warn',
    'prefer-const': 'warn'
  },
  ignorePatterns: [
    'wwwroot/lib/**',       // Ignore third-party libraries
    '**/*.min.js',          // Ignore minified files
    'obj/**',               // Ignore build artifacts
    'bin/**'                // Ignore build artifacts
  ]
};
