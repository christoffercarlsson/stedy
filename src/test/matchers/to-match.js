const toMatch = (received, expected) => {
  if (typeof expected === 'string') {
    return received.includes(expected);
  }
  return new RegExp(expected).test(received);
};

export default toMatch;
