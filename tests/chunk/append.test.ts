import { createFrom, append } from '../../src/chunk'

describe('append', () => {
  it('should append the data from another chunk', () => {
    const a = createFrom('Hel')
    const b = createFrom('lo')
    expect(append(a, b)).toEqual(createFrom('Hello'))
  })
})
