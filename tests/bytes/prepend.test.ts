import { createFrom } from '../../src'

describe('prepend', () => {
  it('should prepend the data from anohter chunk', () => {
    const a = createFrom('lo')
    const b = createFrom('Hel')
    expect(a.prepend(b)).toEqual(createFrom('Hello'))
  })
})
