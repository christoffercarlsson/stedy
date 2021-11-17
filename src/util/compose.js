const head = (funcs) => [funcs[0], funcs.slice(1)]

export const composeAsync = (...funcs) => {
  const [firstFunc, remainingFuncs] = head(funcs)
  return (...args) =>
    remainingFuncs.reduce(
      async (previousPromise, func) => func(await previousPromise),
      firstFunc(...args)
    )
}

export const compose = (...funcs) => {
  const [firstFunc, remainingFuncs] = head(funcs)
  return (...args) =>
    remainingFuncs.reduce(
      (previousValue, func) => func(previousValue),
      firstFunc(...args)
    )
}
