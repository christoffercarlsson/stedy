import { mkdir, rm as removePath } from 'fs/promises'
import {
  isAbsolute as isAbsolutePath,
  resolve as resolvePath
} from 'path/posix'
import { build as esbuild } from 'esbuild'
import { nodeExternalsPlugin } from 'esbuild-node-externals'
import aliasPlugin from 'esbuild-plugin-alias'
import {
  FORMAT_CJS,
  FORMAT_ESM,
  OUTPUT_DIRECTORY,
  TARGET_ES2015,
  TARGET_ES2016,
  TARGET_ES2017,
  TARGET_ES2018,
  TARGET_ES2019,
  TARGET_ES2020,
  TARGET_ESNEXT
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

const isValidTarget = (target) =>
  [
    TARGET_ES2015,
    TARGET_ES2016,
    TARGET_ES2017,
    TARGET_ES2018,
    TARGET_ES2019,
    TARGET_ES2020,
    TARGET_ESNEXT
  ].includes(target)

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

const createAliases = (workingDirectory, aliases) => {
  if (aliases.size === 0) {
    return {}
  }
  return [...aliases].reduce(
    (definitions, [module, path]) => ({
      ...definitions,
      [module]: resolvePath(workingDirectory, path)
    }),
    {}
  )
}

const emptyDir = async (path) => {
  await removePath(path, { force: true, recursive: true })
  await mkdir(path, { recursive: true })
}

const build = async (
  workingDirectory,
  outputDirectory,
  outputBase,
  entryPoints,
  bundle,
  clean,
  aliases,
  include,
  inject,
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
  if (clean) {
    await emptyDir(resolvePath(workingDirectory, outputDirectory))
  }
  return esbuild({
    absWorkingDir: workingDirectory,
    bundle,
    define: createEnvironmentDefinition(environment),
    entryPoints,
    format,
    inject: inject.map((path) => resolvePath(workingDirectory, path)),
    minify,
    outbase: outputBase,
    outdir: outputDirectory,
    platform: 'node',
    plugins: [
      nodeExternalsPlugin({
        packagePath: resolvePath(workingDirectory, 'package.json'),
        allowList: include
      }),
      aliasPlugin(createAliases(workingDirectory, aliases))
    ],
    sourcemap: sourceMaps ? 'external' : false,
    target
  })
}

const ensureArray = (value) => (Array.isArray(value) ? value : [value])

const ensureMap = (value) =>
  value instanceof Map ? value : new Map(Object.entries(value))

const createBuilder =
  ({
    format = FORMAT_ESM,
    outputDirectory = OUTPUT_DIRECTORY,
    minify = true,
    sourceMaps = false,
    target = TARGET_ES2020
  } = {}) =>
  (
    workingDirectory,
    entryPoints,
    {
      alias = {},
      bundle = true,
      clean = true,
      environment = {},
      include = [],
      inject = [],
      outputBase
    } = {}
  ) =>
    build(
      workingDirectory,
      outputDirectory,
      outputBase,
      ensureArray(entryPoints),
      bundle === true,
      clean === true,
      ensureMap(alias),
      ensureArray(include),
      ensureArray(inject),
      ensureMap(environment),
      isValidTarget(target) ? target : TARGET_ES2020,
      format === FORMAT_CJS ? FORMAT_CJS : FORMAT_ESM,
      minify === true,
      sourceMaps === true
    )

export default createBuilder
