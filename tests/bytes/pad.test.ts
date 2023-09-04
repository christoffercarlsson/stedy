import { Bytes } from '../../src/bytes'

describe('pad', () => {
  it('should pad a given chunk with zeroes on the left', () => {
    expect(Bytes.from([1, 2, 3]).padLeft(6)).toEqual(
      Bytes.from([0, 0, 0, 1, 2, 3])
    )
  })

  it('should pad a given chunk with zeroes on the right', () => {
    expect(Bytes.from([1, 2, 3]).padRight(6)).toEqual(
      Bytes.from([1, 2, 3, 0, 0, 0])
    )
  })
})
