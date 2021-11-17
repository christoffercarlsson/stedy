import { describe, it, expect } from '../../src/test.js'
import { createFrom, prepend } from '../../src/chunk.js'

export default describe('prepend', () =>
  it('should prepend the data from anohter chunk', () => {
    const a = createFrom('lo')
    const b = createFrom('Hel')
    expect(prepend(a, b)).toEqual(createFrom('Hello'))
  }))
