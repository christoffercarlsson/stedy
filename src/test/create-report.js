import {
  REPORT_SUMMARY,
  REPORT_RESULTS,
  REPORT_SUMMARY_PASS,
  REPORT_SUMMARY_DURATION,
  REPORT_SUMMARY_ERRORS,
  REPORT_SUMMARY_FAILED_SUITES,
  REPORT_SUMMARY_FAILED_TESTS,
  REPORT_SUMMARY_PASSED_SUITES,
  REPORT_SUMMARY_PASSED_TESTS,
  REPORT_SUMMARY_TOTAL_SUITES,
  REPORT_SUMMARY_TOTAL_TESTS,
  REPORT_SUITE_DESCRIPTION,
  REPORT_SUITE_MODULE,
  REPORT_SUITE_PASS,
  REPORT_SUITE_RESULTS,
  REPORT_TEST_DESCRIPTION,
  REPORT_TEST_DURATION,
  REPORT_TEST_ERROR,
  REPORT_TEST_PASS,
  REPORT_CWD
} from './constants.js'
import { duration, ensureValidPath } from './utils.js'

const addSuiteCount = (summary, pass) => {
  if (pass) {
    summary.set(
      REPORT_SUMMARY_PASSED_SUITES,
      summary.get(REPORT_SUMMARY_PASSED_SUITES) + 1
    )
  } else {
    summary.set(
      REPORT_SUMMARY_FAILED_SUITES,
      summary.get(REPORT_SUMMARY_FAILED_SUITES) + 1
    )
  }
  summary.set(
    REPORT_SUMMARY_TOTAL_SUITES,
    summary.get(REPORT_SUMMARY_TOTAL_SUITES) + 1
  )
}

const addTestCount = (summary) => {
  summary.set(
    REPORT_SUMMARY_TOTAL_TESTS,
    summary.get(REPORT_SUMMARY_TOTAL_TESTS) + 1
  )
}

const addFailure = (summary, error) => {
  summary.set(REPORT_SUMMARY_PASS, false)
  summary.set(REPORT_SUMMARY_ERRORS, [
    ...summary.get(REPORT_SUMMARY_ERRORS),
    error
  ])
  summary.set(
    REPORT_SUMMARY_FAILED_TESTS,
    summary.get(REPORT_SUMMARY_FAILED_TESTS) + 1
  )
  addTestCount(summary)
}

const addSuccess = (summary) => {
  summary.set(
    REPORT_SUMMARY_PASSED_TESTS,
    summary.get(REPORT_SUMMARY_PASSED_TESTS) + 1
  )
  addTestCount(summary)
}

const createTestResult = (description, { duration, error, pass }) => ({
  [REPORT_TEST_DESCRIPTION]: description,
  [REPORT_TEST_DURATION]: duration,
  [REPORT_TEST_ERROR]: error,
  [REPORT_TEST_PASS]: pass
})

const createTestResults = (summary, testResults) => {
  let pass = true
  const results = [...testResults.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, [description, result]]) => {
      if (!result.pass) {
        pass = false
        addFailure(summary, result.error)
      } else {
        addSuccess(summary)
      }
      return createTestResult(description, result)
    })
  return { pass, results }
}

const createResults = (summary, allResults) =>
  [...allResults].map(([moduleName, [description, testResults]]) => {
    const { pass, results } = createTestResults(summary, testResults)
    addSuiteCount(summary, pass)
    return {
      [REPORT_SUITE_DESCRIPTION]: description,
      [REPORT_SUITE_MODULE]: moduleName,
      [REPORT_SUITE_PASS]: pass,
      [REPORT_SUITE_RESULTS]: results
    }
  })

const createSummary = (summaryMap) =>
  [...summaryMap].reduce(
    (summary, [key, value]) => ({
      ...summary,
      [key]: value
    }),
    {}
  )

const createReport = (cwd, results, start) => {
  const summary = new Map([
    [REPORT_SUMMARY_DURATION, duration(start)],
    [REPORT_SUMMARY_ERRORS, []],
    [REPORT_SUMMARY_FAILED_SUITES, 0],
    [REPORT_SUMMARY_PASSED_SUITES, 0],
    [REPORT_SUMMARY_TOTAL_SUITES, 0],
    [REPORT_SUMMARY_FAILED_TESTS, 0],
    [REPORT_SUMMARY_PASSED_TESTS, 0],
    [REPORT_SUMMARY_TOTAL_TESTS, 0],
    [REPORT_SUMMARY_PASS, true]
  ])
  const reportResults = createResults(summary, results)
  const reportSummary = createSummary(summary)
  return {
    [REPORT_CWD]: `/${ensureValidPath(cwd)}`,
    [REPORT_RESULTS]: reportResults,
    [REPORT_SUMMARY]: reportSummary
  }
}

export default createReport
