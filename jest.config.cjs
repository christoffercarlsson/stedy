module.exports = {
  clearMocks: true,
  collectCoverage: true,
  collectCoverageFrom: ['dist/src/**/*.js'],
  coverageDirectory: 'coverage',
  coverageReporters: ['json', 'json-summary', 'html', 'text-summary'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: -10
    }
  },
  testMatch: ['**/dist/tests/**/*.{test,spec}.js']
}
