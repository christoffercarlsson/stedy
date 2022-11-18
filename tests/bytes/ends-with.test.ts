import { concat, createFrom } from '../../src/bytes'

describe('endsWith', () => {
  it('should check to see if a chunk ends with a given chunk', () => {
    const a = createFrom('Hello')
    const b = createFrom(' World')
    const c = createFrom()
    const view = concat([a, b])
    expect(view.endsWith(b)).toBe(true)
    expect(view.endsWith(a)).toBe(false)
    expect(b.endsWith(view)).toBe(false)
    expect(view.endsWith(c)).toBe(false)
    expect(c.endsWith(view)).toBe(false)
    expect(c.endsWith(c)).toBe(true)
    expect(view.endsWith(view)).toBe(true)
  })
})
