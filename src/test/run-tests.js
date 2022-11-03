import { DEFAULT_CONCURRENCY } from './constants.js'
import createReport from './create-report.js'
import loadTests from './load-tests.js'
import { ensureFunc } from './utils.js'

const splitWorkload = (tests, concurrency) => {
  const size =
    concurrency > 0 && concurrency <= Number.MAX_VALUE
      ? concurrency
      : DEFAULT_CONCURRENCY
  if (tests.length <= size) {
    return [tests]
  }
  const length = Math.ceil(tests.length / size)
  return Array.from({ length }, (_, index) => {
    const begin = index * size
    return tests.slice(begin, begin + size)
  })
}

const createReportProgress = (onProgress, totalNumberOfTests) => {
  let totalNumberOfCompletedTests = 0
  const moduleTests = new Map([])
  return async (
    {
      moduleName,
      moduleDescription,
      numberOfTests,
      testIndex,
      testDescription
    },
    testResult
  ) => {
    totalNumberOfCompletedTests += 1
    const numberOfCompletedTests =
      (moduleTests.has(moduleName) ? moduleTests.get(moduleName) : 0) + 1
    moduleTests.set(moduleName, numberOfCompletedTests)
    await onProgress({
      moduleDescription,
      moduleName,
      numberOfTests,
      progress: Math.floor((numberOfCompletedTests / numberOfTests) * 100),
      testDescription,
      testIndex,
      testResult,
      totalNumberOfTests,
      totalNumberOfCompletedTests,
      totalProgress: Math.floor(
        (totalNumberOfCompletedTests / totalNumberOfTests) * 100
      )
    })
  }
}

const sequentially = (funcs) =>
  funcs.reduce(async (previousPromise, func) => {
    await previousPromise
    await func()
  }, Promise.resolve())

const runBatch = (batch, reportProgress) =>
  Promise.all(
    batch.map(async (setupTest) => {
      const { details, test } = setupTest()
      const result = await test()
      await reportProgress(details, result)
    })
  )

const run = (tests, concurrency, onProgress) => {
  const batches = splitWorkload(tests, concurrency)
  const reportProgress = createReportProgress(
    ensureFunc(onProgress),
    tests.length
  )
  return sequentially(
    batches.map((batch) => () => runBatch(batch, reportProgress))
  )
}

const runTests = async (moduleNames, { cwd, concurrency, onProgress }) => {
  const [tests, results] = await loadTests(moduleNames, cwd)
  const start = new Date()
  await run(tests, concurrency, onProgress)
  return createReport(cwd, results, start)
}

export default runTests
