import { cwd, exit } from 'process'
import { cpus } from 'os'
import { globby } from 'globby'
import { run } from '../src/test.js'
;(async () => {
  const { summary } = await run(
    await globby('tests/**/*.test.js', { onlyFiles: true }),
    {
      concurrency: cpus().length,
      cwd: cwd()
    }
  )
  const {
    totalNumberOfTests,
    numberOfPassedTests,
    numberOfFailedTests,
    duration,
    errors
  } = summary
  console.log(
    `Ran ${totalNumberOfTests} tests in ${
      duration / 1000
    } seconds, ${numberOfPassedTests} passed, ${numberOfFailedTests} failed.\n`
  )
  if (errors.length > 0) {
    errors.forEach((error) => {
      console.error(error)
    })
    exit(1)
  }
})()
