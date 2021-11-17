const toBeNumeric = (received) =>
  typeof received === 'number' || typeof received === 'bigint';

export default toBeNumeric;
