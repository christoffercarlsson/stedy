import { describe, it, expect } from '../../dist/test.js'
import { createFrom, hasSize } from '../../dist/chunk.js'

export default describe('hasSize', () =>
  it('should check to see if a chunk is of a given size', () => {
    const view = createFrom('Hello')
    expect(hasSize(view, 5)).toBe(true)
    expect(hasSize(view, 6)).toBe(false)
  }))
