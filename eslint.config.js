import js from '@eslint/js';

// Node built-in globals the code actually uses; no env preset needed.
const nodeGlobals = {
  process: 'readonly',
  Buffer: 'readonly',
  console: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  fetch: 'readonly',
  AbortController: 'readonly',
  TextEncoder: 'readonly',
  TextDecoder: 'readonly',
  crypto: 'readonly'
};

export default [
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: nodeGlobals
    },
    rules: {
      // The CodeQL launch review caught unused imports by hand; this makes
      // that class of miss fail CI instead.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    }
  },
  {
    // The worker runs on Cloudflare's runtime, not Node.
    files: ['cloudflare-worker/**/*.js'],
    languageOptions: {
      globals: {
        Response: 'readonly',
        Request: 'readonly',
        Headers: 'readonly',
        crypto: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly'
      }
    }
  },
  {
    ignores: ['node_modules/**', '.wrangler/**', 'cloudflare-worker/.wrangler/**']
  }
];
