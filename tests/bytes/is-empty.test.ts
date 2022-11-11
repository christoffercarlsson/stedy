import { createFrom, isEmpty } from '../../src/bytes'

describe('isEmpty', () => {
  it('should check to see if the chunk is empty', () => {
    expect(isEmpty(createFrom('Hello'))).toBe(false)
    expect(isEmpty(createFrom())).toBe(true)
  })
})
