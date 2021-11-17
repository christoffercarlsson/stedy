import { ensureFunc } from './utils.js';

export const test = (description, fn) => ({
  description: `${description}`,
  fn: ensureFunc(fn)
});

export default test;
