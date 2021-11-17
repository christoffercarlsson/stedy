export const duration = (start) => {
  const now = new Date();
  return now.valueOf() - start.valueOf();
};

export const ensureArray = (value) => {
  if (Array.isArray(value)) {
    return value;
  }
  if (value === undefined || value === null) {
    return [];
  }
  if (typeof value[Symbol.iterator] === 'function') {
    return [...value];
  }
  return [value];
};

export const ensureFunc = (func) =>
  typeof func === 'function' ? func : () => {};

export const ensureValidPath = (str) =>
  (str || '').replace(/(\\|\/)+/g, '/').replace(/^\/+|\/+$/g, '');
