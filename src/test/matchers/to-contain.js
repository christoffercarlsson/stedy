const toContain = (received, expected) => {
  if (Array.isArray(received) || typeof received === 'string') {
    return received.includes(expected);
  }
  return false;
};

export default toContain;
