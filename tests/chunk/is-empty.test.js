import { describe, it, expect } from '../../dist/test.js'
import { createFrom, isEmpty } from '../../dist/chunk.js'

export default describe('isEmpty', () =>
  it('should check to see if the chunk is empty', () => {
    expect(isEmpty(createFrom('Hello'))).toBe(false)
    expect(isEmpty(createFrom())).toBe(true)
  }))
