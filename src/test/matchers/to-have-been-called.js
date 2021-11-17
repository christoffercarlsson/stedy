import toEqual from './to-equal.js';

const toBeSpy = (fn) => typeof fn === 'function' && Array.isArray(fn.calls);

export const toHaveBeenCalled = (fn) => toBeSpy(fn) && fn.calls.length > 0;

export const toHaveBeenNthCalledWith = (fn, n, ...args) =>
  toHaveBeenCalled(fn) && toEqual(fn.calls[n - 1][0], args);

export const toHaveBeenCalledWith = (fn, ...args) =>
  toHaveBeenNthCalledWith(fn, 1, ...args);

export const toHaveBeenLastCalledWith = (fn, ...args) =>
  toBeSpy(fn) && toHaveBeenNthCalledWith(fn, fn.calls.length, ...args);

export const toHaveBeenCalledTimes = (fn, times) =>
  toBeSpy(fn) && fn.calls.length === times;

export const toHaveNthReturnedWith = (fn, n, value) =>
  toHaveBeenCalled(fn) && toEqual(fn.calls[n - 1][1], value);

export const toHaveLastReturnedWith = (fn, value) =>
  toBeSpy(fn) && toHaveNthReturnedWith(fn, fn.calls.length, value);

export const toHaveReturnedWith = (fn, value) =>
  toHaveNthReturnedWith(fn, 1, value);
