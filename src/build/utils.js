import { createRequire } from 'module'
import {
  isAbsolute as isAbsolutePath,
  resolve as resolvePath
} from 'path/posix'
import {
  JSX_PRESET_PREACT,
  JSX_PRESET_REACT,
  PLATFORM_BROWSER,
  PLATFORM_NEUTRAL,
  PLATFORM_NODE,
  TARGET_ES2015,
  TARGET_ES2016,
  TARGET_ES2017,
  TARGET_ES2018,
  TARGET_ES2019,
  TARGET_ES2020,
  TARGET_ES2021,
  TARGET_ES2022,
  TARGET_ESNEXT
} from './constants.js'

export const ensureArray = (value) => (Array.isArray(value) ? value : [value])

export const ensureMap = (value) => {
  if (value instanceof Map) {
    return value
  }
  if (Array.isArray(value)) {
    return new Map(value)
  }
  return new Map(Object.entries(value))
}

const isRelativePath = (path) => !isAbsolutePath(path)

const isValidEntryPoints = (entryPoints) =>
  Array.isArray(entryPoints) &&
  entryPoints.length > 0 &&
  entryPoints.every(isRelativePath)

export const ensureValidEntryPoints = (entryPoints) => {
  if (!isValidEntryPoints(entryPoints)) {
    throw new Error(
      'Each entry point must be a path relative to the working directory'
    )
  }
  return entryPoints
}

const require = createRequire(import.meta.url)

const isValidJSX = (jsx) =>
  Array.isArray(jsx) &&
  jsx.length === 3 &&
  jsx.every((item) => typeof item === 'string')

export const ensureValidJSX = (jsx) => {
  if (jsx === JSX_PRESET_REACT) {
    return [
      'React.createElement',
      'React.Fragment',
      require.resolve('./react-shim.js')
    ]
  }
  if (jsx === JSX_PRESET_PREACT) {
    return ['h', 'Fragment', require.resolve('./preact-shim.js')]
  }
  if (!isValidJSX(jsx)) {
    throw new Error('Invalid JSX configuration')
  }
  return jsx
}

const isValidPlatform = (platform) =>
  [PLATFORM_BROWSER, PLATFORM_NEUTRAL, PLATFORM_NODE].includes(platform)

export const ensureValidPlatform = (platform) =>
  isValidPlatform(platform) ? platform : PLATFORM_NEUTRAL

const isValidTarget = (target) =>
  [
    TARGET_ES2015,
    TARGET_ES2016,
    TARGET_ES2017,
    TARGET_ES2018,
    TARGET_ES2019,
    TARGET_ES2020,
    TARGET_ES2021,
    TARGET_ES2022,
    TARGET_ESNEXT
  ].includes(target)

export const ensureValidTarget = (target) =>
  isValidTarget(target) ? target : TARGET_ES2020

export const ensureValidOutputDirectory = (workingDirectory, outputDirectory) =>
  resolvePath(workingDirectory, outputDirectory)

export const ensureValidWorkingDirectory = (path) => {
  if (!isAbsolutePath(path)) {
    throw new Error('The working directory must be an absolute path')
  }
  return path
}
