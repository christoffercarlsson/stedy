import {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  LANGUAGE_TYPESCRIPT
} from './lint/constants.js'
import createFormatter from './lint/create-formatter.js'
import createLinter from './lint/create-linter.js'

const format = createFormatter()

const lint = createLinter()

export {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  LANGUAGE_TYPESCRIPT,
  createFormatter,
  createLinter,
  format,
  lint
}
