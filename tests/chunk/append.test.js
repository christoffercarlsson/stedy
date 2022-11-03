import { describe, it, expect } from '../../src/test.js'
import { createFrom, append } from '../../src/chunk.js'

export default describe('append', () =>
  it('should append the data from another chunk', () => {
    const a = createFrom('Hel')
    const b = createFrom('lo')
    expect(append(a, b)).toEqual(createFrom('Hello'))
  }))
