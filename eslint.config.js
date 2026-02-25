import eslint from '@eslint/js';
import prettier from 'eslint-config-prettier';
import importPlugin from 'eslint-plugin-import-x';
import n from 'eslint-plugin-n';
import promise from 'eslint-plugin-promise';
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: ['**/dist/**', '**/node_modules/**', '*.php', 'tests/**', '*.cjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  n.configs['flat/recommended'],
  promise.configs['flat/recommended'],
  {
    plugins: {
      'import-x': importPlugin,
    },

    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        global: 'readonly',
      },
    },

    rules: {
      'n/no-unpublished-import': 'off',
      'n/no-extraneous-import': 'error',
      'n/no-unsupported-features/node-builtins': [
        'error',
        {
          version: '>=25.0.0',
          ignores: [],
        },
      ],

      curly: ['error', 'all'],
      'max-nested-callbacks': ['error', { max: 4 }],
      'max-statements-per-line': ['error', { max: 3 }],
      'no-console': 'off',
      'no-empty-function': 'error',
      'no-floating-decimal': 'error',
      'no-inline-comments': 'error',
      'no-lonely-if': 'error',
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': [
        'error',
        { allow: ['err', 'resolve', 'reject'] },
      ],
      'no-var': 'error',
      'no-undef': 'off',
      'prefer-const': 'error',
      yoda: 'error',

      'no-template-curly-in-string': 'error',
      'no-unreachable-loop': 'error',
      'array-callback-return': 'error',
      'require-await': 'warn',
      'consistent-return': 'warn',
      'prefer-template': 'warn',
      'object-shorthand': ['warn', 'always'],

      'import-x/first': 'error',
      'import-x/order': [
        'warn',
        {
          groups: [
            ['builtin', 'external'],
            ['internal', 'parent', 'sibling', 'index'],
          ],
          alphabetize: { order: 'asc', caseInsensitive: true },
          'newlines-between': 'always',
        },
      ],
      'no-duplicate-imports': 'error',
      'n/no-missing-import': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['**/scripts/**/*.mjs'],
    rules: { 'n/no-process-exit': 'off' },
  },
  prettier,
];
