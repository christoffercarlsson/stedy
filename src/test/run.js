import { isWebEnvironment } from '../util.js'
import runTests from './run-tests.js'

const createRunnerWithCoverage = (moduleNames, options) => async () => {
  const { runTestsWithCoverage } = await import('./coverage.js')
  return runTestsWithCoverage(moduleNames, options)
}

const createRunnerWithoutCoverage = (moduleNames, options) => async () => {
  const report = await runTests(moduleNames, options)
  return { report, coverage: null }
}

const createRunner = (moduleNames, options) => {
  return options.collectCoverage === true && !isWebEnvironment()
    ? createRunnerWithCoverage(moduleNames, options)
    : createRunnerWithoutCoverage(moduleNames, options)
}

const run = (moduleNames, options = {}) => createRunner(moduleNames, options)()

export default run
