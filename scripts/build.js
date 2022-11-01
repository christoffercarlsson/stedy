import { copyFile } from 'fs/promises'
import { createRequire } from 'module'
import { exit } from 'process'
import { globby } from 'globby'
import { build, bundle } from '../src/build.js'

const require = createRequire(import.meta.url)

const findBuildFiles = async (excludeFiles) => {
  const files = await globby('src/**/*.js', {
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
    'src/code/parsers/graphql.js',
    'src/code/parsers/html.js',
    'src/code/parsers/markdown.js',
    'src/code/parsers/yaml.js',
    'src/code/prettier.js'
  ]
  await bundle(bundleFiles, {
    alias: {
      assert: require.resolve('assert-browserify'),
      path: require.resolve('path-browserify'),
      util: require.resolve('util/')
    },
    clean: true,
    platform: 'browser'
  })
  await build(await findBuildFiles(bundleFiles))
  await copyFile(
    'src/build/typescript-esbuild.json',
    'dist/build/typescript-esbuild.json'
  )
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
