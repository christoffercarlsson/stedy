const partial =
  (func, ...partials) =>
  (...args) =>
    func(...partials.concat(args))

export default partial
