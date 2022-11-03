import { ensureArray, ensureFunc } from './utils.js'

export const suite = (description, fn) => ({
  description: `${description}`,
  fn: async () => {
    const tests = await ensureFunc(fn)()
    return ensureArray(tests)
  }
})

export default suite
