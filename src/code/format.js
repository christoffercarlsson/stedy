import { partial } from '../util.js'
import {
  ensureSupportedLanguage,
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  // LANGUAGE_TYPESCRIPT
  LANGUAGE_YAML,
  PARSER_CSS,
  PARSER_HTML,
  PARSER_JAVASCRIPT,
  PARSER_JSON,
  PARSER_MARKDOWN,
  // PARSER_TYPESCRIPT
  PARSER_YAML
} from './language.js'
import parserBabel from './parsers/babel.js'
import parserCSS from './parsers/css.js'
import parserHTML from './parsers/html.js'
import parserMarkdown from './parsers/markdown.js'
import parserYAML from './parsers/yaml.js'
import prettier, { config as defaultOptions } from './prettier.js'

const parsers = new Map([
  [LANGUAGE_CSS, [PARSER_CSS, [parserCSS]]],
  [LANGUAGE_HTML, [PARSER_HTML, [parserBabel, parserCSS, parserHTML]]],
  [
    LANGUAGE_JAVASCRIPT,
    [PARSER_JAVASCRIPT, [parserBabel, parserCSS, parserHTML]]
  ],
  [LANGUAGE_JSON, [PARSER_JSON, [parserBabel]]],
  [
    LANGUAGE_MARKDOWN,
    [PARSER_MARKDOWN, [parserBabel, parserCSS, parserHTML, parserMarkdown]]
  ],
  // [
  //   LANGUAGE_TYPESCRIPT,
  //   [PARSER_TYPESCRIPT, [parserBabel, parserCSS, parserHTML]]
  // ],
  [LANGUAGE_YAML, [PARSER_YAML, [parserYAML]]]
])

const formatSource = async (options, onError, language, source) => {
  try {
    const [parser, plugins] = parsers.get(
      await ensureSupportedLanguage(language)
    )
    const formatted = prettier.format(source, {
      ...defaultOptions,
      ...options,
      parser,
      plugins
    })
    return formatted
  } catch (error) {
    if (typeof onError === 'function') {
      onError(error)
    }
    return typeof source === 'string' ? source : ''
  }
}

export const createFormatter = (options = {}, onError) =>
  partial(formatSource, options, onError)

export const format = createFormatter()
