import { resolve as resolvePath } from 'path/posix'
import { cwd, exit } from 'process'
import { createRequire } from 'module'
import { build } from '../src/build.js'

const require = createRequire(import.meta.url)

const workingDirectory = cwd()

const run = async () => {
  await build(
    workingDirectory,
    [
      'src/build.js',
      'src/chunk.js',
      'src/code/language.js',
      'src/code/parsers/babel.js',
      'src/code/parsers/css.js',
      'src/code/parsers/html.js',
      'src/code/parsers/markdown.js',
      'src/code/prettier.js',
      'src/crypto.js',
      'src/test.js',
      'src/util.js'
    ],
    {
      include: ['@christoffercarlsson/prettier-config', 'prettier']
    }
  )
  await build(workingDirectory, 'src/code/lint.js', {
    alias: {
      assert: require.resolve('assert-browserify'),
      path: require.resolve('path-browserify'),
      tty: require.resolve('tty-browserify'),
      util: resolvePath(workingDirectory, 'node_modules/util/util.js')
    },
    clean: false,
    include: [
      '@christoffercarlsson/eslint-config',
      'assert-browserify',
      'eslint',
      'path-browserify',
      'process',
      'tty-browserify',
      'util'
    ],
    inject: 'src/code/process-shim.js',
    outputBase: 'src'
  })
  await build(
    workingDirectory,
    ['src/code/format.js', 'src/code/parse.js', 'src/code.js'],
    {
      bundle: false,
      clean: false
    }
  )
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
