import { createFrom } from '../../src'

describe('read', () => {
  it('should read data sequentially', () => {
    const [a, b] = createFrom('Hello World').read(5)
    expect(a).toEqual(createFrom('Hello'))
    expect(b).toEqual(createFrom(' World'))
  })

  it('should read data sequentially in multiple parts', () => {
    const [a, b, c, d] = createFrom('Hello World, good sir!').read(5, 0, 6)
    expect(a).toEqual(createFrom('Hello'))
    expect(b).toEqual(createFrom(''))
    expect(c).toEqual(createFrom(' World'))
    expect(d).toEqual(createFrom(', good sir!'))
  })
})
