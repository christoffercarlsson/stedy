import { fork } from 'child_process'
import { mkdtemp, readFile } from 'fs/promises'
import { globby } from 'globby'
import istanbulCoverage from 'istanbul-lib-coverage'
import istanbulReport from 'istanbul-lib-report'
import istanbulReports from 'istanbul-reports'
import { createRequire } from 'module'
import { tmpdir } from 'os'
import { join as joinPath, resolve as resolvePath } from 'path'
import process from 'process'
import { fileURLToPath } from 'url'
import convertToIstanbul from 'v8-to-istanbul'
import {
  COVERAGE_MESSAGE_TYPE_PROGRESS,
  COVERAGE_MESSAGE_TYPE_REPORT,
  COVERAGE_TMP_DIR_PREFIX,
  DEFAULT_COLLECT_COVERAGE_FROM
} from './constants.js'
import { ensureFunc } from './utils.js'

const { createCoverageMap } = istanbulCoverage
const { createContext: createReportContext } = istanbulReport
const { create: createReport } = istanbulReports

export const startCoverageCollection = async () => {
  const coverageDirectory = await mkdtemp(
    joinPath(tmpdir(), COVERAGE_TMP_DIR_PREFIX)
  )
  process.env.NODE_V8_COVERAGE = coverageDirectory
  return coverageDirectory
}

const filterCoverageResults = (results, modulePaths, pathPrefix) =>
  results.reduce((finalResults, result) => {
    if (!result.url.startsWith('file:///')) {
      return finalResults
    }
    const path = fileURLToPath(result.url)
    if (
      !modulePaths.includes(path) &&
      !path.startsWith(`${pathPrefix}/node_modules`) &&
      path.startsWith(pathPrefix) &&
      (path.endsWith('.js') || path.endsWith('.mjs') || path.endsWith('.cjs'))
    ) {
      return [...finalResults, { path, coverage: result.functions }]
    }
    return finalResults
  }, [])

const loadCoverageFiles = async (coverageDirectory) => {
  const files = await globby('*.json', {
    cwd: coverageDirectory,
    absolute: true
  })
  const results = await Promise.all(
    files.map(async (path) => {
      const contents = await readFile(path, 'utf-8')
      return JSON.parse(contents).result
    })
  )
  return results.flat()
}

const convertCoverage = async ({ path, coverage }) => {
  const converter = convertToIstanbul(path)
  await converter.load()
  converter.applyCoverage(coverage)
  return converter.toIstanbul()
}

const convertResults = async (results) => {
  const map = createCoverageMap()
  const convertedResults = await Promise.all(
    results.map((result) => convertCoverage(result))
  )
  convertedResults.forEach((data) => {
    map.merge(data)
  })
  return map
}

const readCoverageReport = async (coverageDirectory) => {
  const report = JSON.parse(
    await readFile(`${coverageDirectory}/coverage-final.json`, 'utf-8')
  )
  return Object.values(report)
}

const createCoverageReport = async (
  coverageThreshold,
  coverageDirectory,
  results
) => {
  const coverageMap = await convertResults(results)
  const watermarks = {
    statements: [50, 80],
    functions: [50, 80],
    branches: [50, 80],
    lines: [50, 80]
  }
  const context = createReportContext({
    dir: coverageDirectory,
    defaultSummarizer: 'nested',
    watermarks,
    coverageMap
  })
  const report = createReport('json', {
    skipEmpty: false,
    skipFull: false
  })
  report.execute(context)
  return readCoverageReport(coverageDirectory)
}

export const stopCoverageCollection = async (
  moduleNames,
  cwd,
  collectCoverageFrom,
  coverageThreshold,
  coverageDirectory
) => {
  const pathPrefix = resolvePath(cwd, collectCoverageFrom)
  const modulePaths = moduleNames.map((name) => resolvePath(cwd, name))
  const results = filterCoverageResults(
    await loadCoverageFiles(coverageDirectory),
    modulePaths,
    pathPrefix
  )
  return createCoverageReport(coverageThreshold, coverageDirectory, results)
}

const createSubprocess = (cwd) => {
  const modulePath = createRequire(import.meta.url).resolve(
    './coverage/subprocess.js'
  )
  return fork(modulePath, { cwd })
}

const runSubprocess = (moduleNames, cwd, concurrency, onProgress) =>
  new Promise((resolve, reject) => {
    let report = {}
    const child = createSubprocess(cwd)
    child
      .on('message', (message) => {
        if (message.type === COVERAGE_MESSAGE_TYPE_PROGRESS) {
          onProgress(message.progress)
        } else if (message.type === COVERAGE_MESSAGE_TYPE_REPORT) {
          report = message.report
        }
      })
      .on('error', reject)
      .on('close', () => {
        resolve(report)
      })
      .send({ moduleNames, cwd, concurrency })
  })

export const runTestsWithCoverage = async (
  moduleNames,
  {
    cwd,
    concurrency,
    onProgress,
    collectCoverageFrom = DEFAULT_COLLECT_COVERAGE_FROM,
    coverageThreshold
  }
) => {
  const coverageDirectory = await startCoverageCollection()
  const report = await runSubprocess(
    moduleNames,
    cwd,
    concurrency,
    ensureFunc(onProgress)
  )
  return {
    report,
    coverage: await stopCoverageCollection(
      moduleNames,
      cwd,
      collectCoverageFrom,
      coverageThreshold,
      coverageDirectory
    )
  }
}
