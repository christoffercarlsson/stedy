import toBeLessThan from './to-be-less-than.js'

const toBeLessThanOrEqual = (received, expected) =>
  toBeLessThan(received, expected) || received === expected

export default toBeLessThanOrEqual
