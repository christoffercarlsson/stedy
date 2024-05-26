import { createFrom } from '../../src'

describe('hasSize', () => {
  it('should check to see if a chunk is of a given size', () => {
    const view = createFrom('Hello')
    expect(view.hasSize(5)).toBe(true)
    expect(view.hasSize(6)).toBe(false)
  })
})
