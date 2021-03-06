import { createFormatter, format } from './code/format.js'
import {
  getLanguages,
  isSupportedLanguage,
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN
} from './code/language.js'
import { createLinter, lint } from './code/lint.js'
import parse from './code/parse.js'

export {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  getLanguages,
  isSupportedLanguage,
  createFormatter,
  createLinter,
  format,
  lint,
  parse
}
