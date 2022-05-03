import { describe, it, expect } from '../../dist/test.js'
import { createFrom, append } from '../../dist/chunk.js'

export default describe('append', () =>
  it('should append the data from another chunk', () => {
    const a = createFrom('Hel')
    const b = createFrom('lo')
    expect(append(a, b)).toEqual(createFrom('Hello'))
  }))
