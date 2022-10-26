export const LANGUAGE_CSS = 'css'
export const LANGUAGE_HTML = 'html'
export const LANGUAGE_GRAPHQL = 'graphql'
export const LANGUAGE_JAVASCRIPT = 'javascript'
export const LANGUAGE_JSON = 'json'
export const LANGUAGE_MARKDOWN = 'markdown'
// export const LANGUAGE_TYPESCRIPT = 'typescript'
export const LANGUAGE_YAML = 'yaml'
export const PARSER_CSS = 'css'
export const PARSER_GRAPHQL = 'graphql'
export const PARSER_HTML = 'html'
export const PARSER_JAVASCRIPT = 'babel'
export const PARSER_JSON = 'json-stringify'
export const PARSER_MARKDOWN = 'markdown'
// export const PARSER_TYPESCRIPT = 'babel-ts'
export const PARSER_YAML = 'yaml'

export const getLanguages = () => [
  LANGUAGE_CSS,
  PARSER_GRAPHQL,
  LANGUAGE_HTML,
  LANGUAGE_JAVASCRIPT,
  LANGUAGE_JSON,
  LANGUAGE_MARKDOWN,
  // LANGUAGE_TYPESCRIPT
  LANGUAGE_YAML
]

export const isSupportedLanguage = (language) =>
  getLanguages().includes(language)

export const ensureSupportedLanguage = (language) => {
  if (!isSupportedLanguage(language)) {
    return Promise.reject(new Error('Unsupported language'))
  }
  return Promise.resolve(language)
}
