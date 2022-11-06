import { concat, createFrom, startsWith } from '../../src/chunk'

describe('startsWith', () => {
  it('should check to see if a chunk starts with a given chunk', () => {
    const a = createFrom('Hello')
    const b = createFrom(' World')
    const c = createFrom()
    const view = concat([a, b])
    expect(startsWith(view, a)).toBe(true)
    expect(startsWith(view, b)).toBe(false)
    expect(startsWith(a, view)).toBe(false)
    expect(startsWith(c, view)).toBe(false)
    expect(startsWith(view, c)).toBe(false)
    expect(startsWith(c, c)).toBe(true)
    expect(startsWith(view, view)).toBe(true)
  })
})
