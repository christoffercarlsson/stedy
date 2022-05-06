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
} from './build/constants.js'
import { createBuild, createBundle } from './build/create-build.js'

const build = createBuild()
const bundle = createBundle()

export {
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
  TARGET_ESNEXT,
  createBuild,
  createBundle,
  build,
  bundle
}
