import { Chunk } from '../../src/bytes'

describe('pad', () => {
  it('should pad a given chunk with zeroes on the left', () => {
    expect(Chunk.from([1, 2, 3]).padLeft(6)).toEqual(
      Chunk.from([0, 0, 0, 1, 2, 3])
    )
  })

  it('should pad a given chunk with zeroes on the right', () => {
    expect(Chunk.from([1, 2, 3]).padRight(6)).toEqual(
      Chunk.from([1, 2, 3, 0, 0, 0])
    )
  })
})
