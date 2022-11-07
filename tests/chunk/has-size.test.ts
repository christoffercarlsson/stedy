import { createFrom, hasSize } from '../../src/chunk'

describe('hasSize', () => {
  it('should check to see if a chunk is of a given size', () => {
    const view = createFrom('Hello')
    expect(hasSize(view, 5)).toBe(true)
    expect(hasSize(view, 6)).toBe(false)
  })
})
