import { xor } from '../../src/chunk'

describe('xor', () => {
  it('should calculate the XOR of two given chunks of the same size', () => {
    const a = Uint8Array.from([
      0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216
    ])
    const b = Uint8Array.from([
      0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195
    ])
    const result = Uint8Array.from([
      0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27
    ])
    expect(xor(a, b)).toEqual(result)
    expect(xor(b, a)).toEqual(result)
    expect(xor(result, b)).toEqual(a)
    expect(xor(result, a)).toEqual(b)
  })

  it('should calculate the XOR of two given chunks that are not the same size', () => {
    const a = Uint8Array.from([74, 48, 144, 63, 12, 153])
    const b = Uint8Array.from([0, 72, 36, 54, 102, 75, 228, 139, 34, 254, 249])
    const result = Uint8Array.from([
      0, 72, 36, 54, 102, 1, 212, 27, 29, 242, 96
    ])
    expect(xor(a, b)).toEqual(result)
    expect(xor(b, a)).toEqual(result)
    expect(xor(result, b)).toEqual(
      Uint8Array.from([0, 0, 0, 0, 0].concat([...a]))
    )
    expect(xor(result, a)).toEqual(b)
  })

  it('should handle invalid input gracefully', () => {
    const view = Uint8Array.from([144, 162, 250, 128, 64, 42, 119, 120, 114])
    expect(xor(view)).toEqual(view)
    expect(xor()).toEqual(Uint8Array.from([]))
  })
})
