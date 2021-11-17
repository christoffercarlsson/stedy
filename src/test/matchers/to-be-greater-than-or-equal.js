import toBeGreaterThan from './to-be-greater-than.js';

const toBeGreaterThanOrEqual = (received, expected) =>
  toBeGreaterThan(received, expected) || received === expected;

export default toBeGreaterThanOrEqual;
