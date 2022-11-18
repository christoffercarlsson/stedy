import { Chunk } from '../../src/bytes'

describe('trim', () => {
  const view = Chunk.from([1, 2, 3])

  it('should trim leading zeroes', () => {
    expect(Chunk.from([0, 0, 0, 1, 2, 3]).trimLeft()).toEqual(view)
  })

  it('should trim trailing zeroes', () => {
    expect(Chunk.from([1, 2, 3, 0, 0, 0]).trimRight()).toEqual(view)
  })

  it('should trim leading bytes', () => {
    expect(Chunk.from([2, 2, 2, 1, 2, 3]).trimLeft(2)).toEqual(view)
  })

  it('should trim trailing bytes', () => {
    expect(Chunk.from([1, 2, 3, 255, 255, 255]).trimRight(255)).toEqual(view)
  })

  it('should treat invalid byte values as zero', () => {
    const left = Chunk.from([0, 0, 0, 1, 2, 3])
    const right = Chunk.from([1, 2, 3, 0, 0, 0])
    expect(left.trimLeft(-1)).toEqual(view)
    expect(left.trimLeft(256)).toEqual(view)
    expect(right.trimRight(-1)).toEqual(view)
    expect(right.trimRight(256)).toEqual(view)
  })
})
