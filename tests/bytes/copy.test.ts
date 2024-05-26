import { Bytes } from '../../src'

describe('copy', () => {
  it('should create a copy of a given chunk', () => {
    const view = Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    expect(view.copy()).toEqual(view)
    expect(view.copy()).not.toBe(view)
  })
})
