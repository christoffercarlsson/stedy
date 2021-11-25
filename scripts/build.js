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
      'src/crypto.js',
      'src/test.js',
      'src/util.js'
    ],
    {
      include: ['esbuild-node-externals', 'esbuild-plugin-alias', 'fs-extra']
    }
  )
  await build(workingDirectory, 'src/lint.js', {
    alias: {
      assert: require.resolve('assert-browserify'),
      path: require.resolve('path-browserify'),
      tty: require.resolve('tty-browserify'),
      util: resolvePath(workingDirectory, 'node_modules/util/util.js')
    },
    clean: false,
    include: [
      '@christoffercarlsson/eslint-config',
      '@christoffercarlsson/prettier-config',
      'assert-browserify',
      'eslint',
      'path-browserify',
      'prettier',
      'prettier-linter-helpers',
      'tty-browserify',
      'util'
    ]
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
