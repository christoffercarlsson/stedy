import { describe, it, expect, fn } from '../../dist/test.js'
import { composeAsync } from '../../dist/util.js'

export default describe('composeAsync', () =>
  it('should compose a given list of functions that each might return a promise', async () => {
    const sleep = (milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds))
    const add = fn(async (x, y) => {
      await sleep(42)
      return x + y
    })
    const square = fn((n) => n * n)
    const result = await composeAsync(add, square)(1, 2)
    expect(add).toHaveBeenCalledWith(1, 2)
    expect(square).toHaveBeenCalledWith(3)
    expect(result).toBe(9)
  }))
