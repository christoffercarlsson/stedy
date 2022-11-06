module.exports = {
  root: true,
  env: {
    browser: true,
    es2020: true,
    'jest/globals': true,
    node: true
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true,
      impliedStrict: true
    },
    tsconfigRootDir: __dirname,
    project: ['./tsconfig.json']
  },
  plugins: ['import', 'jest', 'node', 'promise', '@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:node/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'plugin:jest/recommended',
    'plugin:promise/recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'standard',
    'prettier'
  ],
  settings: {
    'import/parsers': {
      '@typescript-eslint/parser': ['.ts', '.tsx']
    },
    'import/resolver': {
      typescript: {
        alwaysTryTypes: true
      }
    }
  },
  rules: {
    'no-bitwise': 'off',
    'no-restricted-syntax': 'off',
    'node/no-missing-import': 'off'
  }
}
