import { concat, createFrom, endsWith } from '../../src/chunk'

describe('endsWith', () => {
  it('should check to see if a chunk ends with a given chunk', () => {
    const a = createFrom('Hello')
    const b = createFrom(' World')
    const c = createFrom()
    const view = concat([a, b])
    expect(endsWith(view, b)).toBe(true)
    expect(endsWith(view, a)).toBe(false)
    expect(endsWith(b, view)).toBe(false)
    expect(endsWith(c, view)).toBe(false)
    expect(endsWith(view, c)).toBe(false)
    expect(endsWith(c, c)).toBe(true)
    expect(endsWith(view, view)).toBe(true)
  })
})
