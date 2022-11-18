import { createFrom } from '../../src/bytes'

describe('append', () => {
  it('should append the data from another chunk', () => {
    const a = createFrom('Hel')
    const b = createFrom('lo')
    expect(a.append(b)).toEqual(createFrom('Hello'))
  })
})
