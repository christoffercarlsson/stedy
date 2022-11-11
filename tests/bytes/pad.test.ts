import { padLeft, padRight } from '../../src/bytes'

describe('pad', () => {
  it('should pad a given chunk with zeroes on the left', () => {
    expect(padLeft(Uint8Array.from([1, 2, 3]), 6)).toEqual(
      Uint8Array.from([0, 0, 0, 1, 2, 3])
    )
  })

  it('should pad a given chunk with zeroes on the right', () => {
    expect(padRight(Uint8Array.from([1, 2, 3]), 6)).toEqual(
      Uint8Array.from([1, 2, 3, 0, 0, 0])
    )
  })
})
