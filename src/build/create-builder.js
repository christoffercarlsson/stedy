import {
  isAbsolute as isAbsolutePath,
  resolve as resolvePath
} from 'path/posix'
import { build as esbuild } from 'esbuild'
import { nodeExternalsPlugin } from 'esbuild-node-externals'
import { emptyDir } from 'fs-extra'
import {
  FORMAT_CJS,
  FORMAT_ESM,
  OUTPUT_DIRECTORY,
  TARGET_ES2020
} from './constants.js'

const isValidExternals = (externals) =>
  Array.isArray(externals) &&
  externals.every(
    (external) => typeof external === 'string' && external.length > 0
  )

const isValidEntryPoints = (entryPoints) =>
  Array.isArray(entryPoints) &&
  entryPoints.length > 0 &&
  entryPoints.every(
    (entryPoint) =>
      typeof entryPoint === 'string' && !isAbsolutePath(entryPoint)
  )

const createEnvironmentDefinition = (environment) => {
  if (environment.size === 0) {
    return undefined
  }
  return [...environment].reduce(
    (definitions, [key, value]) => ({
      ...definitions,
      [`process.env.${key}`]: JSON.stringify(value)
    }),
    {}
  )
}

const build = async (
  workingDirectory,
  outputDirectory,
  entryPoints,
  include,
  environment,
  target,
  format,
  minify,
  sourceMaps
) => {
  if (!isAbsolutePath(workingDirectory)) {
    throw new Error('The working directory must be an absolute path')
  }
  if (!isValidEntryPoints(entryPoints)) {
    throw new Error(
      'Each entry point must be a path relative to the working directory'
    )
  }
  if (!isValidExternals(include)) {
    throw new Error(
      'Unable to determine which external packages to include in the bundle'
    )
  }
  await emptyDir(resolvePath(workingDirectory, outputDirectory))
  await esbuild({
    absWorkingDir: workingDirectory,
    bundle: true,
    define: createEnvironmentDefinition(environment),
    entryPoints,
    format,
    minify,
    outdir: outputDirectory,
    platform: 'node',
    plugins: [
      nodeExternalsPlugin({
        packagePath: resolvePath(workingDirectory, 'package.json'),
        allowList: include
      })
    ],
    sourcemap: sourceMaps ? 'external' : false,
    target
  })
}

const createBuilder =
  ({
    format = FORMAT_ESM,
    outputDirectory = OUTPUT_DIRECTORY,
    minify = true,
    sourceMaps = false,
    target = TARGET_ES2020
  } = {}) =>
  async (workingDirectory, entryPoints, options = {}) => {
    const { include = [], environment = {} } = options
    await build(
      workingDirectory,
      outputDirectory,
      Array.isArray(entryPoints) ? entryPoints : [entryPoints],
      Array.isArray(include) ? include : [include],
      environment instanceof Map
        ? environment
        : new Map(Object.entries(environment)),
      target,
      format === FORMAT_CJS ? FORMAT_CJS : FORMAT_ESM,
      minify === true,
      sourceMaps === true
    )
  }

export default createBuilder
