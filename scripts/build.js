import { resolve as resolvePath } from 'path/posix'
import { cwd, exit } from 'process'
import { createRequire } from 'module'
import { globby } from 'globby'
import { build } from '../src/build.js'

const require = createRequire(import.meta.url)

const workingDirectory = cwd()

const findBuildFiles = async (bundleFiles, shims) => {
  const files = await globby('src/**/*.js', {
    cwd: workingDirectory,
    onlyFiles: true
  })
  return files.filter(
    (path) => !bundleFiles.includes(path) && !shims.includes(path)
  )
}

const run = async () => {
  const bundleFiles = [
    'src/build/plugins.js',
    'src/code/lint.js',
    'src/code/parsers/babel.js',
    'src/code/parsers/css.js',
    'src/code/parsers/html.js',
    'src/code/parsers/markdown.js',
    'src/code/prettier.js',
    'src/crypto/curve25519.js'
  ]
  const shims = ['src/code/process-shim.js']
  await build(workingDirectory, bundleFiles, {
    alias: {
      assert: require.resolve('assert-browserify'),
      buffer: require.resolve('buffer/'),
      crypto: require.resolve('crypto-browserify'),
      events: require.resolve('events/'),
      path: require.resolve('path-browserify'),
      process: require.resolve('process/'),
      string_decoder: require.resolve('string_decoder/'),
      stream: require.resolve('stream-browserify'),
      tty: require.resolve('tty-browserify'),
      util: resolvePath(workingDirectory, 'node_modules/util/util.js')
    },
    inject: shims
  })
  await build(workingDirectory, await findBuildFiles(bundleFiles, shims), {
    bundle: false,
    clean: false
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
