import { isAbsolute as isAbsolutePath } from 'path/posix'
import {
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
  isValidTarget(target) ? target : TARGET_ESNEXT

export const ensureValidOutputDirectory = (path) => {
  if (!isRelativePath(path)) {
    throw new Error(
      'The output directory must be relative to the working directory'
    )
  }
  return path
}

export const ensureValidWorkingDirectory = (path) => {
  if (!isAbsolutePath(path)) {
    throw new Error('The working directory must be an absolute path')
  }
  return path
}
