import { createFrom, equals } from '../../src/chunk'

describe('equals', () => {
  it('should check to see if the chunk is equal to another chunk', () => {
    const greeting = 'Hello World!'
    const view = createFrom(greeting)
    expect(equals(view, createFrom(greeting))).toBe(true)
    expect(equals(view, createFrom('Hello'))).toBe(false)
    expect(equals(createFrom('Hello'), view)).toBe(false)
    expect(equals(createFrom(), view)).toBe(false)
    expect(equals(view, createFrom())).toBe(false)
    expect(equals(createFrom(), createFrom())).toBe(true)
  })
})
