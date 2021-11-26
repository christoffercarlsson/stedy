import {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  LANGUAGE_TYPESCRIPT
} from './format/constants.js'
import createFormatter from './format/create-formatter.js'

const format = createFormatter()

export {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  LANGUAGE_TYPESCRIPT,
  createFormatter,
  format
}
