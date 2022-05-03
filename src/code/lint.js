import { Linter } from '../../node_modules/eslint/lib/linter/linter.js'
import defaultConfig from '@christoffercarlsson/eslint-config'
import { partial } from '../util.js'

const getConfig = (config) => ({
  ...defaultConfig,
  ...config,
  rules: {
    ...defaultConfig.rules,
    ...(config && config.rules ? config.rules : {})
  }
})

const lintSource = async (config, source, fix = false) => {
  const linter = new Linter()
  if (fix === true) {
    const { fixed, output, messages } = linter.verifyAndFix(source, config)
    return { fixed, source: output, messages }
  }
  const messages = linter.verify(source, config)
  return { fixed: false, source, messages }
}

export const createLinter = (config = {}) =>
  partial(lintSource, getConfig(config))

export const lint = createLinter()
