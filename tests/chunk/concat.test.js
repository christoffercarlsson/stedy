import { describe, it, expect } from '../../src/test.js'
import { concat } from '../../src/chunk.js'

export default describe('concat', () => [
  it('should create a new chunk by concatenating all the chunks in a given list together', () => {
    const view = concat([
      Uint8Array.from([72, 101, 108, 108]),
      Uint8Array.from([111, 32, 87]),
      Uint8Array.from([111, 114, 108])
    ])
    expect(view).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  }),

  it('should create an empty chunk on invalid input', () => {
    const view = concat('hubba')
    expect(view).toEqual(Uint8Array.from([]))
  })
])
