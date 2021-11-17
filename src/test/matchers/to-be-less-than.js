import toBeNumeric from './to-be-numeric.js';

const toBeLessThan = (received, expected) =>
  toBeNumeric(received) && received < expected;

export default toBeLessThan;
