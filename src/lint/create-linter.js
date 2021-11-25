import { Linter } from 'eslint/lib/linter/linter.js'
import { showInvisibles, generateDifferences } from 'prettier-linter-helpers'
import defaultConfig from '@christoffercarlsson/eslint-config'
import {
  FORMAT_MESSAGE_DELETE,
  FORMAT_MESSAGE_INSERT,
  FORMAT_MESSAGE_REPLACE,
  FORMAT_RULE,
  LANGUAGE_JAVASCRIPT
} from './constants.js'
import { createFormatterSync } from './create-formatter.js'

const { INSERT, DELETE, REPLACE } = generateDifferences

const getConfig = (config) => ({
  ...defaultConfig,
  ...config,
  rules: {
    ...defaultConfig.rules,
    ...(config && config.rules ? config.rules : {}),
    [FORMAT_RULE]: ['error']
  }
})

const getLoc = (context, [start, end]) => {
  const sourceCode = context.getSourceCode()
  return {
    start: sourceCode.getLocFromIndex(start),
    end: sourceCode.getLocFromIndex(end)
  }
}

const reportDifference = (
  context,
  { operation: messageId, offset, deleteText = '', insertText = '' }
) => {
  const data = {
    deleteText: showInvisibles(deleteText),
    insertText: showInvisibles(insertText)
  }
  const range = [offset, offset + deleteText.length]
  context.report({
    messageId,
    data,
    loc: getLoc(context, range),
    fix: (fixer) => fixer.replaceTextRange(range, insertText)
  })
}

const createFormatRule = (options) => {
  const format = createFormatterSync(options)
  return {
    meta: {
      type: 'layout',
      fixable: 'code',
      messages: {
        [DELETE]: FORMAT_MESSAGE_DELETE,
        [INSERT]: FORMAT_MESSAGE_INSERT,
        [REPLACE]: FORMAT_MESSAGE_REPLACE
      }
    },
    create: (context) => ({
      Program() {
        const source = context.getSourceCode().text
        const formatted = format(source, LANGUAGE_JAVASCRIPT)
        if (source !== formatted) {
          generateDifferences(source, formatted).forEach((difference) => {
            reportDifference(context, difference)
          })
        }
      }
    })
  }
}

const createLinterMethods = (options) => {
  const { lint: lintOptions = {}, format: formatOptions = {} } = options
  const config = getConfig(lintOptions)
  const linter = new Linter()
  linter.defineRule(FORMAT_RULE, createFormatRule(formatOptions))
  return {
    verify: (source) => {
      const messages = linter.verify(source, config)
      return { fixed: false, source, messages }
    },
    verifyAndFix: (source) => {
      const { fixed, output, messages } = linter.verifyAndFix(source, config)
      return { fixed, source: output, messages }
    }
  }
}

const createLinter = (options = {}) => {
  const { verify, verifyAndFix } = createLinterMethods(options)
  return async (source, fix = false) => {
    if (fix === true) {
      return verifyAndFix(source)
    }
    return verify(source)
  }
}

export default createLinter
