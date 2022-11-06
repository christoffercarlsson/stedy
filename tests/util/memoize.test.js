import { jest } from '@jest/globals'
import { memoize } from '../../src/util'

describe('memoize', () => {
  it('should cache the results of function calls', () => {
    const fn = jest.fn((n) => n + 1)
    const memo = memoize(fn)
    const results = [memo(1), memo(2), memo(1)]
    expect(fn).toHaveBeenCalledTimes(2)
    expect(results).toEqual([2, 3, 2])
  })

  it('should allow the user to control how the caching key is resolved', () => {
    const fn = jest.fn((n) => n + 1)
    const memo = memoize(fn, (n) => n - 1)
    const results = [memo(1), memo(2), memo(1)]
    expect(fn).toHaveBeenCalledTimes(2)
    expect(results).toEqual([2, 3, 2])
  })
})
