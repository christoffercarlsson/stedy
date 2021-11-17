import {
  FORMAT_CJS,
  FORMAT_ESM,
  TARGET_ES2015,
  TARGET_ES2016,
  TARGET_ES2017,
  TARGET_ES2018,
  TARGET_ES2019,
  TARGET_ES2020,
  TARGET_ESNEXT
} from './build/constants.js'
import createBuilder from './build/create-builder.js'

const build = createBuilder()

export {
  FORMAT_CJS,
  FORMAT_ESM,
  TARGET_ES2015,
  TARGET_ES2016,
  TARGET_ES2017,
  TARGET_ES2018,
  TARGET_ES2019,
  TARGET_ES2020,
  TARGET_ESNEXT,
  createBuilder,
  build
}
