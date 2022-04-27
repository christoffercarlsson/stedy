import { mkdir, rm as removePath } from 'fs/promises'
import { builtinModules as nodeCoreModules } from 'module'
import {
  isAbsolute as isAbsolutePath,
  resolve as resolvePath
} from 'path/posix'
import { build as esbuild } from 'esbuild'
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
import { aliasPlugin } from './plugins.js'

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

const createEnvironmentDefinition = (environment) =>
  [...environment].reduce(
    (definitions, [key, value]) => ({
      ...definitions,
      [`process.env.${key}`]: JSON.stringify(value)
    }),
    {
      global: 'globalThis'
    }
  )

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

const getExternals = (aliases) => [
  'esbuild',
  ...nodeCoreModules.filter((name) => !aliases.has(name))
]

const build = async (
  workingDirectory,
  outputDirectory,
  outputBase,
  entryPoints,
  bundle,
  clean,
  aliases,
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
  if (clean) {
    await emptyDir(resolvePath(workingDirectory, outputDirectory))
  }
  return esbuild({
    absWorkingDir: workingDirectory,
    bundle,
    define: createEnvironmentDefinition(environment),
    entryPoints: entryPoints.filter(
      (entryPoint) => !inject.includes(entryPoint)
    ),
    external: bundle ? getExternals(aliases) : undefined,
    format,
    inject: inject.map((path) => resolvePath(workingDirectory, path)),
    minify,
    outbase: outputBase,
    outdir: outputDirectory,
    platform: 'browser',
    plugins: [aliasPlugin(createAliases(workingDirectory, aliases))],
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
      ensureArray(inject),
      ensureMap(environment),
      isValidTarget(target) ? target : TARGET_ES2020,
      format === FORMAT_CJS ? FORMAT_CJS : FORMAT_ESM,
      minify === true,
      sourceMaps === true
    )

export default createBuilder
