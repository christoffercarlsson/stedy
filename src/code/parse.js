import {
  ensureSupportedLanguage,
  LANGUAGE_CSS,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  // LANGUAGE_TYPESCRIPT,
  PARSER_CSS,
  PARSER_HTML,
  PARSER_JAVASCRIPT,
  PARSER_JSON,
  PARSER_MARKDOWN
  // PARSER_TYPESCRIPT
} from './language.js'
import parserBabel from './parsers/babel.js'
import parserCSS from './parsers/css.js'
import parserHTML from './parsers/html.js'
import parserMarkdown from './parsers/markdown.js'

const getParser = (parser, name) => {
  const { parse } = parser.parsers[name]
  const options = name === PARSER_CSS ? { parser: PARSER_CSS } : {}
  return { parse, options }
}

const parsers = new Map([
  [LANGUAGE_CSS, getParser(parserCSS, PARSER_CSS)],
  [LANGUAGE_HTML, getParser(parserHTML, PARSER_HTML)],
  [LANGUAGE_JAVASCRIPT, getParser(parserBabel, PARSER_JAVASCRIPT)],
  [LANGUAGE_JSON, getParser(parserBabel, PARSER_JSON)],
  [LANGUAGE_MARKDOWN, getParser(parserMarkdown, PARSER_MARKDOWN)]
  // [LANGUAGE_TYPESCRIPT, getParser(parserBabel, PARSER_TYPESCRIPT)],
])

const parseSource = async (language, source) => {
  const { parse, options } = parsers.get(
    await ensureSupportedLanguage(language)
  )
  return parse(source, {}, options)
}

export default parseSource
