import { cwd, exit } from 'process'
import { createRequire } from 'module'
import { globby } from 'globby'
import { build } from '../src/build.js'

const require = createRequire(import.meta.url)
const workingDirectory = cwd()
const outputBase = 'src'
const bundleForBrowserFiles = [
  'src/code/lint.js',
  'src/code/parsers/babel.js',
  'src/code/parsers/css.js',
  'src/code/parsers/html.js',
  'src/code/parsers/markdown.js',
  'src/code/prettier.js'
]
const bundleForNodeFiles = ['src/build/plugins.js', 'src/crypto/curve25519.js']
const excludeBuildFiles = [...bundleForBrowserFiles, ...bundleForNodeFiles]

const findBuildFiles = async () => {
  const files = await globby('src/**/*.js', {
    cwd: workingDirectory,
    onlyFiles: true
  })
  return files.filter((path) => !excludeBuildFiles.includes(path))
}

const run = async () => {
  await build(workingDirectory, bundleForBrowserFiles, {
    alias: {
      assert: require.resolve('assert-browserify'),
      path: require.resolve('path-browserify'),
      util: require.resolve('util/')
    },
    mainFields: ['browser', 'main', 'module'],
    outputBase
  })
  await build(workingDirectory, bundleForNodeFiles, {
    clean: false,
    mainFields: ['module', 'main'],
    outputBase
  })
  await build(workingDirectory, await findBuildFiles(), {
    bundle: false,
    clean: false,
    outputBase
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
