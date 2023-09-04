import { Bytes, concat } from '../../src/bytes'

describe('concat', () => {
  it('should create a new chunk by concatenating all the chunks in a given list together', () => {
    const view = concat([
      Uint8Array.from([72, 101, 108, 108]),
      Bytes.from([111, 32, 87]),
      Uint8Array.from([111, 114, 108])
    ])
    expect(view).toEqual(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  })
})
