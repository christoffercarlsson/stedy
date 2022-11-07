import { copy } from '../../src/chunk'

describe('copy', () => {
  it('should create a copy of a given chunk', () => {
    const view = Uint8Array.from([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108
    ])
    expect(copy(view)).toEqual(view)
    expect(copy(view)).not.toBe(view)
  })
})
