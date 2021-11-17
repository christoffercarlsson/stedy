import toBeNumeric from './to-be-numeric.js';

const toBeGreaterThan = (received, expected) =>
  toBeNumeric(received) && received > expected;

export default toBeGreaterThan;
