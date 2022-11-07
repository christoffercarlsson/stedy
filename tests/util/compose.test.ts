import { jest } from '@jest/globals'
import { compose } from '../../src/util'

describe('compose', () => {
  it('should compose a given list of functions', () => {
    const add = jest.fn((x: number, y: number) => x + y)
    const square = jest.fn((n: number) => n * n)
    const result = compose(add, square)(1, 2) as number
    expect(add).toHaveBeenCalledWith(1, 2)
    expect(square).toHaveBeenCalledWith(3)
    expect(result).toBe(9)
  })
})
