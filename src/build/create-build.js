import { mkdir as createPath, rm as removePath } from 'fs/promises'
import { builtinModules as nodeCoreModules } from 'module'
import { resolve as resolvePath } from 'path/posix'
import { cwd } from 'process'
import { build as esbuild } from 'esbuild'
import {
  JSX_PRESET_REACT,
  OUTPUT_DIRECTORY,
  PLATFORM_BROWSER,
  PLATFORM_NEUTRAL,
  TARGET_ES2020
} from './constants.js'
import { aliasPlugin } from './plugins.js'
import {
  ensureArray,
  ensureMap,
  ensureValidJSX,
  ensureValidOutputDirectory,
  ensureValidPlatform,
  ensureValidTarget,
  ensureValidWorkingDirectory
} from './utils.js'

const createDefine = (environment) =>
  [...environment].reduce(
    (definitions, [key, value]) => ({
      ...definitions,
      [`process.env.${key}`]: JSON.stringify(value)
    }),
    {
      global: 'globalThis'
    }
  )

const createEntryPoints = (entryPoints, inject) =>
  entryPoints.filter((entryPoint) => !inject.includes(entryPoint))

const createExternal = (bundle, platform, aliases) => {
  if (!bundle || platform === PLATFORM_BROWSER) {
    return undefined
  }
  return ['esbuild', ...nodeCoreModules.filter((name) => !aliases.has(name))]
}

const hasJSXEntryPoint = (entryPoints) =>
  entryPoints.some((entryPoint) => entryPoint.endsWith('.jsx'))

const createInject = (workingDirectory, inject, entryPoints, jsxShim) => {
  const paths = inject.map((path) => resolvePath(workingDirectory, path))
  if (hasJSXEntryPoint(entryPoints)) {
    return [...paths, resolvePath(workingDirectory, jsxShim)]
  }
  return paths
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

const createPlugins = (workingDirectory, aliases) => [
  aliasPlugin(createAliases(workingDirectory, aliases))
]

const emptyDirectory = async (path) => {
  await removePath(path, { force: true, recursive: true })
  await createPath(path, { recursive: true })
}

const build = async (
  workingDirectory,
  outputDirectory,
  entryPoints,
  aliases,
  inject,
  environment,
  target,
  platform,
  [jsxFactory, jsxFragment, jsxShim],
  bundle,
  clean,
  minify,
  sourceMaps
) => {
  if (clean) {
    await emptyDirectory(resolvePath(workingDirectory, outputDirectory))
  }
  return esbuild({
    absWorkingDir: workingDirectory,
    bundle,
    define: createDefine(environment),
    entryPoints: createEntryPoints(entryPoints, inject),
    external: createExternal(bundle, platform, aliases),
    format: 'esm',
    inject: createInject(workingDirectory, inject, entryPoints, jsxShim),
    jsxFactory,
    jsxFragment,
    minify,
    outdir: outputDirectory,
    platform,
    plugins: createPlugins(workingDirectory, aliases),
    sourcemap: sourceMaps ? 'external' : false,
    target
  })
}

export const createBuild =
  ({
    bundle = false,
    minify = false,
    outputDirectory = OUTPUT_DIRECTORY,
    sourceMaps = false,
    target = TARGET_ES2020,
    workingDirectory = cwd()
  } = {}) =>
  (
    entryPoints,
    {
      alias = {},
      clean = false,
      environment = {},
      inject = [],
      jsx = JSX_PRESET_REACT,
      platform = PLATFORM_NEUTRAL
    } = {}
  ) =>
    build(
      ensureValidWorkingDirectory(workingDirectory),
      ensureValidOutputDirectory(outputDirectory),
      ensureArray(entryPoints),
      ensureMap(alias),
      ensureArray(inject),
      ensureMap(environment),
      ensureValidTarget(target),
      ensureValidPlatform(platform),
      ensureValidJSX(jsx),
      bundle === true,
      clean === true,
      minify === true,
      sourceMaps === true
    )

export const createBundle = (options) =>
  createBuild({ minify: true, ...options, bundle: true })
