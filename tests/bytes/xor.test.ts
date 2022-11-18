import { Chunk } from '../../src/bytes'

describe('xor', () => {
  it('should calculate the XOR of two given chunks of the same size', () => {
    const a = Chunk.from([0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216])
    const b = Chunk.from([
      0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195
    ])
    const result = Chunk.from([
      0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27
    ])
    expect(a.xor(b)).toEqual(result)
    expect(b.xor(a)).toEqual(result)
    expect(result.xor(b)).toEqual(a)
    expect(result.xor(a)).toEqual(b)
  })

  it('should calculate the XOR of two given chunks that are not the same size', () => {
    const a = Chunk.from([74, 48, 144, 63, 12, 153])
    const b = Chunk.from([0, 72, 36, 54, 102, 75, 228, 139, 34, 254, 249])
    const result = Chunk.from([0, 72, 36, 54, 102, 1, 212, 27, 29, 242, 96])
    expect(a.xor(b)).toEqual(result)
    expect(b.xor(a)).toEqual(result)
    expect(result.xor(b)).toEqual(Chunk.from([0, 0, 0, 0, 0]).append(a))
    expect(result.xor(a)).toEqual(b)
  })

  it('should handle invalid input gracefully', () => {
    const view = Chunk.from([144, 162, 250, 128, 64, 42, 119, 120, 114])
    expect(view.xor(undefined)).toEqual(view)
    expect(view.xor(null)).toEqual(view)
  })
})
