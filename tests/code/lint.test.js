import { describe, it, expect } from '../../dist/test.js'
import { lint } from '../../dist/code.js'

export default describe('lint', () => [
  it('should verify a given source code against linting rules', async () => {
    const source = 'var foo = true;'
    const result = await lint(source)
    expect(result.fixed).toBe(false)
    expect(result.source).toEqual(source)
    expect(result.messages.length).toBe(2)
    expect(result.messages[0].ruleId).toEqual('no-var')
    expect(result.messages[1].ruleId).toEqual('no-unused-vars')
  }),

  it('should verify and fix a given source code according to linting rules', async () => {
    const result = await lint('var foo = true;', true)
    expect(result.fixed).toBe(true)
    expect(result.source).toEqual('const foo = true;')
    expect(result.messages.length).toBe(1)
    expect(result.messages[0].ruleId).toEqual('no-unused-vars')
  })
])
