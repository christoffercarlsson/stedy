import { cwd, exit } from 'process'
import { cpus } from 'os'
import { globby } from 'globby'
import { run as runTests } from '../dist/test.js'

const run = async () => {
  const { summary, results } = await runTests(
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
    results
      .filter((result) => !result.pass)
      .map((result) => ({
        ...result,
        results: result.results.filter((r) => !r.pass)
      }))
      .forEach((result) => {
        console.log(JSON.stringify(result, null, 2))
      })
    exit(1)
  }
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
