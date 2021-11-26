import { Linter } from 'eslint/lib/linter/linter.js'
import defaultConfig from '@christoffercarlsson/eslint-config'

const getConfig = (config) => ({
  ...defaultConfig,
  ...config,
  rules: {
    ...defaultConfig.rules,
    ...(config && config.rules ? config.rules : {})
  }
})

const createLinter = (options = {}) => {
  const config = getConfig(options)
  const linter = new Linter()
  return async (source, fix = false) => {
    if (fix === true) {
      const { fixed, output, messages } = linter.verifyAndFix(source, config)
      return { fixed, source: output, messages }
    }
    const messages = linter.verify(source, config)
    return { fixed: false, source, messages }
  }
}

export default createLinter
