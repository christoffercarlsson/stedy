import AssertionError from './assertion-error.js'
import * as MATCHERS from './matchers.js'

const expectationFailed = (matches, isNot) => !(isNot ? !matches : matches)

const getOperator = (matcher, isNot) => `${isNot ? 'not.' : ''}${matcher}`

const getErrorProps = (matcher, received, isNot, params) => ({
  actual: received,
  expected: params[0],
  operator: getOperator(matcher, isNot),
  params: params.slice(1)
})

const createMatcher =
  (name, received, isNot) =>
  (...params) => {
    const matches = MATCHERS[name](received, ...params)
    if (matches instanceof Promise) {
      return matches.then((m) => {
        if (expectationFailed(m, isNot)) {
          return Promise.reject(
            new AssertionError(getErrorProps(name, received, isNot, params))
          )
        }
        return true
      })
    }
    if (expectationFailed(matches, isNot)) {
      throw new AssertionError(getErrorProps(name, received, isNot, params))
    }
    return true
  }

const createMatchers = (received, isNot) =>
  Object.keys(MATCHERS).reduce(
    (matchers, name) => ({
      ...matchers,
      [name]: createMatcher(name, received, isNot)
    }),
    {}
  )

const createExpect = (received, isNot = false) => {
  const matchers = createMatchers(received, isNot)
  if (isNot) {
    return matchers
  }
  return {
    get not() {
      return createExpect(received, true)
    },
    ...matchers
  }
}

const expect = (received) => createExpect(received)

export default expect
