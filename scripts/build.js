import { resolve as resolvePath } from 'path/posix'
import { cwd, exit } from 'process'
import { createRequire } from 'module'
import { globby } from 'globby'
import { build } from '../src/build.js'

const require = createRequire(import.meta.url)

const workingDirectory = cwd()

const findBuildFiles = async (bundleFiles) => {
  const files = await globby('src/**/*.js', { onlyFiles: true })
  return files.filter((path) => !bundleFiles.includes(path))
}

const run = async () => {
  const bundleFiles = [
    'src/code/lint.js',
    'src/code/parsers/babel.js',
    'src/code/parsers/css.js',
    'src/code/parsers/html.js',
    'src/code/parsers/markdown.js',
    'src/code/prettier.js',
    'src/crypto/curve25519.js'
  ]
  await build(workingDirectory, bundleFiles, {
    alias: {
      assert: require.resolve('assert-browserify'),
      crypto: require.resolve('crypto-browserify'),
      path: require.resolve('path-browserify'),
      tty: require.resolve('tty-browserify'),
      util: resolvePath(workingDirectory, 'node_modules/util/util.js')
    },
    clean: false,
    include: [
      '@christoffercarlsson/eslint-config',
      '@christoffercarlsson/prettier-config',
      '@noble/ed25519',
      'assert-browserify',
      'crypto-browserify',
      'eslint',
      'path-browserify',
      'prettier',
      'process',
      'tty-browserify',
      'util'
    ],
    inject: 'src/code/process-shim.js'
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
