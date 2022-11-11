import { createFrom, read } from '../../src/bytes'

describe('read', () => {
  it('should read data sequentially', () => {
    const [a, b] = read(createFrom('Hello World'), 5)
    expect(a).toEqual(createFrom('Hello'))
    expect(b).toEqual(createFrom(' World'))
  })

  it('should read data sequentially in multiple parts', () => {
    const [a, b, c, d] = read(createFrom('Hello World, good sir!'), 5, 0, 6)
    expect(a).toEqual(createFrom('Hello'))
    expect(b).toEqual(createFrom(''))
    expect(c).toEqual(createFrom(' World'))
    expect(d).toEqual(createFrom(', good sir!'))
  })
})
