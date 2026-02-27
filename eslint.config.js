import eslint from '@eslint/js';
import prettier from 'eslint-config-prettier';
import importPlugin from 'eslint-plugin-import-x';
import n from 'eslint-plugin-n';
import promise from 'eslint-plugin-promise';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: ['**/dist/**', '**/node_modules/**', '*.php', 'tests/**', '*.cjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
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
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['server/**/*.{ts,tsx}', 'scripts/**/*.mjs'],
    plugins: {
      n,
      promise,
    },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      ...n.configs['flat/recommended'].rules,
      ...promise.configs['flat/recommended'].rules,
      'n/no-unpublished-import': 'off',
      'n/no-extraneous-import': 'error',
      'n/no-process-exit': 'off',
      'n/no-missing-import': 'off',
      'n/no-unsupported-features/node-builtins': [
        'error',
        {
          version: '>=25.0.0',
          ignores: [],
        },
      ],
    },
  },
  {
    files: ['client/**/*.{ts,tsx}'],
    plugins: {
      react,
      'react-hooks': reactHooks,
    },
    settings: {
      react: { version: 'detect' },
    },
    languageOptions: {
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        HTMLElement: 'readonly',
        MouseEvent: 'readonly',
        KeyboardEvent: 'readonly',
        fetch: 'readonly',
        Headers: 'readonly',
      },
    },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  prettier,
];
