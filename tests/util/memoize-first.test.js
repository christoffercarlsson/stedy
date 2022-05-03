import { describe, it, expect, spy } from '../../dist/test.js'
import { memoizeFirst } from '../../dist/util.js'

export default describe('memoizeFirst', () =>
  it('should cache and always return the result of the first function call', () => {
    const fn = spy((n) => n + 1)
    const memo = memoizeFirst(fn)
    const results = [memo(1), memo(42), memo(17)]
    expect(fn).toHaveBeenCalledTimes(1)
    expect(results).toEqual([2, 2, 2])
  }))
