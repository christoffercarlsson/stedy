import { concat, createFrom } from '../../src'

describe('startsWith', () => {
  it('should check to see if a chunk starts with a given chunk', () => {
    const a = createFrom('Hello')
    const b = createFrom(' World')
    const c = createFrom()
    const view = concat([a, b])
    expect(view.startsWith(a)).toBe(true)
    expect(view.startsWith(b)).toBe(false)
    expect(a.startsWith(view)).toBe(false)
    expect(c.startsWith(view)).toBe(false)
    expect(view.startsWith(c)).toBe(false)
    expect(c.startsWith(c)).toBe(true)
    expect(view.startsWith(view)).toBe(true)
  })
})
