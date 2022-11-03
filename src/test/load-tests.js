import { duration, ensureArray, ensureValidPath } from './utils.js'

const success = (start) => ({
  pass: true,
  duration: duration(start),
  error: null
})

const failure = (start, error) => ({
  pass: false,
  duration: duration(start),
  error
})

const runTest = async (fn) => {
  const start = new Date()
  try {
    await fn()
    return success(start)
  } catch (error) {
    return failure(start, error)
  }
}

const setupTests = (moduleName, moduleDescription, tests, results) =>
  tests.map(({ description: testDescription, fn }, testIndex) => () => ({
    details: {
      moduleName,
      moduleDescription,
      numberOfTests: tests.length,
      testIndex,
      testDescription
    },
    test: async () => {
      const result = await runTest(fn)
      results.set(testIndex, [testDescription, result])
      return result
    }
  }))

const getModulePath = (moduleName, cwd) => {
  const prefix = ensureValidPath(cwd)
  const suffix = ensureValidPath(moduleName).replace(
    new RegExp(`^${prefix}`),
    ''
  )
  return `/${prefix}/${suffix}`
}

const loadModule = async (allResults, moduleName, cwd) => {
  const {
    default: { description, fn }
  } = await import(getModulePath(moduleName, cwd))
  const results = new Map([])
  const tests = setupTests(
    moduleName,
    description,
    ensureArray(await fn()),
    results
  )
  allResults.set(moduleName, [description, results])
  return tests
}

const loadTests = async (moduleNames, cwd) => {
  const results = new Map([])
  const tests = await Promise.all(
    ensureArray(moduleNames).map((moduleName) =>
      loadModule(results, `${moduleName}`, `${cwd}`)
    )
  )
  return [tests.flat(), results]
}

export default loadTests
