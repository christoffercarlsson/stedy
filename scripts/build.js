import { cwd, exit } from 'process'
import { createRequire } from 'module'
import { globby } from 'globby'
import { build } from '../src/build.js'

const require = createRequire(import.meta.url)
const workingDirectory = cwd()

const findBuildFiles = async (excludeFiles) => {
  const files = await globby('src/**/*.js', {
    cwd: workingDirectory,
    onlyFiles: true
  })
  return files.filter((path) => !excludeFiles.includes(path))
}

const run = async () => {
  const bundleFiles = [
    'src/build/plugins.js',
    'src/code/lint.js',
    'src/code/parsers/babel.js',
    'src/code/parsers/css.js',
    'src/code/parsers/html.js',
    'src/code/parsers/markdown.js',
    'src/code/prettier.js'
  ]
  await build(workingDirectory, bundleFiles, {
    alias: {
      assert: require.resolve('assert-browserify'),
      path: require.resolve('path-browserify'),
      util: require.resolve('util/')
    },
    mainFields: ['browser', 'main', 'module']
  })
  await build(workingDirectory, await findBuildFiles(bundleFiles), {
    bundle: false,
    clean: false
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
