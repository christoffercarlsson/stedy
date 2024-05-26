import { createFrom } from '../../src'

describe('isEmpty', () => {
  it('should check to see if the chunk is empty', () => {
    expect(createFrom('Hello').isEmpty()).toBe(false)
    expect(createFrom().isEmpty()).toBe(true)
  })
})
