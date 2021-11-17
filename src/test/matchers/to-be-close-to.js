const isInfinity = (received, expected) =>
  (received === Infinity && expected === Infinity) ||
  (received === -Infinity && expected === -Infinity);

const toBeCloseTo = (received, expected, precision = 2) => {
  if (isInfinity(received, expected)) {
    return true;
  }
  const expectedDiff = 10 ** -precision / 2;
  const receivedDiff = Math.abs(expected - received);
  return receivedDiff < expectedDiff;
};

export default toBeCloseTo;
