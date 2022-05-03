import { describe, it, expect, fn } from '../../dist/test.js'
import { compose } from '../../dist/util.js'

export default describe('compose', () =>
  it('should compose a given list of functions', () => {
    const add = fn((x, y) => x + y)
    const square = fn((n) => n * n)
    const result = compose(add, square)(1, 2)
    expect(add).toHaveBeenCalledWith(1, 2)
    expect(square).toHaveBeenCalledWith(3)
    expect(result).toBe(9)
  }))
