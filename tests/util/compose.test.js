import { jest } from '@jest/globals'
import { compose } from '../../src/util'

describe('compose', () => {
  it('should compose a given list of functions', () => {
    const add = jest.fn((x, y) => x + y)
    const square = jest.fn((n) => n * n)
    const result = compose(add, square)(1, 2)
    expect(add).toHaveBeenCalledWith(1, 2)
    expect(square).toHaveBeenCalledWith(3)
    expect(result).toBe(9)
  })
})
