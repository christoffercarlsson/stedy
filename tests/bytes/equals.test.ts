import { createFrom } from '../../src/bytes'

describe('equals', () => {
  it('should check to see if the chunk is equal to another chunk', () => {
    const greeting = 'Hello World!'
    const view = createFrom(greeting)
    expect(view.equals(createFrom(greeting))).toBe(true)
    expect(view.equals(createFrom('Hello'))).toBe(false)
    expect(createFrom('Hello').equals(view)).toBe(false)
    expect(createFrom().equals(view)).toBe(false)
    expect(view.equals(createFrom())).toBe(false)
    expect(createFrom().equals(createFrom())).toBe(true)
  })
})
