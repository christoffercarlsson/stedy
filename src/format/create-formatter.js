import prettier from 'prettier/esm/standalone.mjs'
import parserBabel from 'prettier/esm/parser-babel.mjs'
import parserCSS from 'prettier/esm/parser-postcss.mjs'
import parserHTML from 'prettier/esm/parser-html.mjs'
import parserMarkdown from 'prettier/esm/parser-markdown.mjs'
import defaultOptions from '@christoffercarlsson/prettier-config'
import {
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  LANGUAGE_TYPESCRIPT,
  PARSER_CSS,
  PARSER_HTML,
  PARSER_JAVASCRIPT,
  PARSER_JSON,
  PARSER_MARKDOWN,
  PARSER_TYPESCRIPT
} from './constants.js'

const parsers = new Map([
  [LANGUAGE_CSS, [PARSER_CSS, [parserCSS]]],
  [LANGUAGE_HTML, [PARSER_HTML, [parserBabel, parserCSS, parserHTML]]],
  [
    LANGUAGE_JAVASCRIPT,
    [PARSER_JAVASCRIPT, [parserBabel, parserCSS, parserHTML]]
  ],
  [
    LANGUAGE_TYPESCRIPT,
    [PARSER_TYPESCRIPT, [parserBabel, parserCSS, parserHTML]]
  ],
  [LANGUAGE_JSON, [PARSER_JSON, [parserBabel]]],
  [
    LANGUAGE_MARKDOWN,
    [PARSER_MARKDOWN, [parserBabel, parserCSS, parserHTML, parserMarkdown]]
  ]
])

const isSupportedLanguage = (language) =>
  [
    LANGUAGE_CSS,
    LANGUAGE_HTML,
    LANGUAGE_JAVASCRIPT,
    LANGUAGE_JSON,
    LANGUAGE_MARKDOWN,
    LANGUAGE_TYPESCRIPT
  ].includes(language)

const format = (options, source, language) => {
  if (!isSupportedLanguage(language)) {
    throw new Error('Unsupported language')
  }
  const [parser, plugins] = parsers.get(language)
  return prettier.format(source, {
    ...defaultOptions,
    ...options,
    parser,
    plugins
  })
}

const createFormatter =
  (options = {}, onError) =>
  async (source, language) => {
    try {
      return format(options, source, language)
    } catch (error) {
      if (typeof onError === 'function') {
        onError(error)
      }
      return typeof source === 'string' ? source : ''
    }
  }

export default createFormatter
