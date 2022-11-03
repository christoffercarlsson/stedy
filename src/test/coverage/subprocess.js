import process from 'process'
import {
  COVERAGE_MESSAGE_TYPE_PROGRESS,
  COVERAGE_MESSAGE_TYPE_REPORT
} from '../constants.js'
import runTests from '../run-tests.js'

process.on('message', async ({ moduleNames, cwd, concurrency }) => {
  const report = await runTests(moduleNames, {
    cwd,
    concurrency,
    onProgress: (progress) => {
      process.send({
        type: COVERAGE_MESSAGE_TYPE_PROGRESS,
        progress
      })
    }
  })
  process.send({
    type: COVERAGE_MESSAGE_TYPE_REPORT,
    report
  })
  setTimeout(() => {
    process.exit(0)
  }, 50)
})
