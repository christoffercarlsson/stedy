export const spy = (fn) => {
  const calls = [];
  const recorder = (...args) => {
    const result = fn(...args);
    calls.push([args, result]);
    return result;
  };
  recorder.calls = calls;
  return recorder;
};

export default spy;
