import { mkdir as createPath, rm as removePath } from 'fs/promises'
import { builtinModules as nodeCoreModules, createRequire } from 'module'
import { resolve as resolvePath } from 'path/posix'
import { cwd as getCwd } from 'process'
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
  entryPoints.some(
    (entryPoint) => entryPoint.endsWith('.jsx') || entryPoint.endsWith('.tsx')
  )

const createInject = (workingDirectory, inject, entryPoints, jsxShim) => {
  const paths = inject.map((path) => resolvePath(workingDirectory, path))
  if (hasJSXEntryPoint(entryPoints)) {
    return [...paths, resolvePath(workingDirectory, jsxShim)]
  }
  return paths
}

const createPlatform = (platform, entryPoints) =>
  hasJSXEntryPoint(entryPoints) ? PLATFORM_BROWSER : platform

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

const createPlugins = (workingDirectory, plugins, aliases) => [
  ...plugins,
  aliasPlugin(createAliases(workingDirectory, aliases))
]

const emptyDirectory = async (path) => {
  await removePath(path, { force: true, recursive: true })
  await createPath(path, { recursive: true })
}

const getTypeScriptConfigPath = () =>
  createRequire(import.meta.url).resolve('./typescript-esbuild.json')

const build = async (
  workingDirectory,
  outputDirectory,
  plugins,
  entryPoints,
  aliases,
  inject,
  environment,
  target,
  targetPlatform,
  [jsxFactory, jsxFragment, jsxShim],
  bundle,
  clean,
  minify,
  sourceMaps
) => {
  if (clean) {
    await emptyDirectory(outputDirectory)
  }
  const platform = createPlatform(targetPlatform, entryPoints)
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
    outbase: workingDirectory,
    outdir: outputDirectory,
    platform,
    plugins: createPlugins(workingDirectory, plugins, aliases),
    sourcemap: sourceMaps ? 'external' : false,
    target,
    tsconfig: getTypeScriptConfigPath()
  })
}

export const createBuild =
  ({
    bundle = false,
    minify = false,
    outputDirectory = OUTPUT_DIRECTORY,
    plugins = [],
    target = TARGET_ES2020,
    cwd = getCwd()
  } = {}) =>
  (
    entryPoints,
    {
      alias = {},
      clean = false,
      environment = {},
      inject = [],
      jsx = JSX_PRESET_REACT,
      platform = PLATFORM_NEUTRAL,
      sourceMaps = false
    } = {}
  ) =>
    build(
      ensureValidWorkingDirectory(cwd),
      ensureValidOutputDirectory(cwd, outputDirectory),
      ensureArray(plugins),
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
