import { describe, it, expect } from '../../dist/test.js'
import { createFrom, prepend } from '../../dist/chunk.js'

export default describe('prepend', () =>
  it('should prepend the data from anohter chunk', () => {
    const a = createFrom('lo')
    const b = createFrom('Hel')
    expect(prepend(a, b)).toEqual(createFrom('Hello'))
  }))
