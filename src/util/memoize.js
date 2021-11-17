const resolveKey = (args, resolver) =>
  typeof resolver === 'function' ? resolver(...args) : args.toString()

export const memoize = (fn, resolver) => {
  const cache = new Map([])
  return (...args) => {
    const key = resolveKey(args, resolver)
    if (cache.has(key)) {
      return cache.get(key)
    }
    const result = fn(...args)
    cache.set(key, result)
    return result
  }
}

export const memoizeFirst = (fn) => memoize(fn, () => 0)
