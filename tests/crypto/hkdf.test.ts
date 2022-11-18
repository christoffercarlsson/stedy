import { createHash } from '../../src'
import { Chunk } from '../../src/bytes'

describe('hkdf', () => {
  const ikm = Chunk.from([
    141, 241, 178, 6, 28, 107, 47, 8, 106, 78, 71, 39, 119, 222, 12, 119, 129,
    195, 193, 244, 244, 141, 188, 196, 247, 28, 67, 149, 190, 55, 187, 178
  ])
  const salt = Chunk.from([
    181, 22, 123, 170, 54, 160, 197, 195, 99, 130, 109, 36, 7, 46, 187, 141
  ])
  const info = Chunk.from([225, 104, 38, 9, 70, 227, 194, 206])
  const algorithms = [
    {
      algorithm: 'SHA-256',
      okm: Chunk.from([
        214, 74, 37, 80, 89, 56, 144, 25, 4, 245, 81, 12, 238, 120, 161, 209,
        139, 29, 211, 229, 86, 41, 209, 137, 214, 190, 104, 5, 147, 32, 155, 34,
        184, 111, 167, 210, 55, 206, 130, 37, 240, 227, 225, 25, 243, 84, 205,
        217, 84, 47, 25, 55, 36, 128, 8, 78, 51, 134, 121, 179, 152, 108, 136,
        140, 82, 189, 197, 34, 245, 13, 25, 110, 218, 42, 152, 13, 188, 72, 223,
        222, 60, 169, 12, 235, 253, 43, 15, 137, 220, 139, 190, 110, 172, 135,
        205, 12
      ])
    },
    {
      algorithm: 'SHA-384',
      okm: Chunk.from([
        4, 167, 17, 228, 99, 79, 96, 230, 189, 11, 226, 216, 95, 103, 158, 109,
        35, 29, 60, 98, 85, 46, 219, 231, 152, 182, 194, 169, 109, 87, 206, 91,
        38, 248, 136, 1, 203, 197, 170, 105, 38, 51, 209, 206, 26, 145, 76, 212
      ])
    },
    {
      algorithm: 'SHA-512',
      okm: Chunk.from([
        56, 56, 203, 230, 33, 255, 251, 216, 178, 222, 128, 206, 21, 180, 1,
        230, 137, 97, 40, 169, 221, 110, 173, 147, 162, 132, 32, 44, 215, 29,
        229, 185, 114, 178, 90, 104, 181, 214, 16, 193, 125, 53, 242, 38, 154,
        208, 243, 133, 198, 70, 103, 242, 122, 179, 242, 134, 198, 72, 129, 125,
        207, 163, 40, 2, 236, 41, 205, 238, 90, 230, 0, 145, 53, 50, 45, 73,
        186, 92, 132, 167, 107, 27, 80, 213, 110, 243, 9, 3, 151, 79, 221, 20,
        186, 76, 110, 67
      ])
    }
  ]

  algorithms.forEach(({ algorithm, okm }) =>
    it(`should derive new a key using HKDF with ${algorithm}`, async () => {
      const { hkdf } = createHash(algorithm)
      expect(await hkdf(ikm, salt, info, okm.byteLength)).toEqual(okm)
    })
  )

  it('should derive a key with the size of the given hash function when the last argument is omitted', async () => {
    const { algorithm, okm } = algorithms[2]
    const { hkdf } = createHash(algorithm)
    expect(await hkdf(ikm, salt, info)).toEqual(okm.subarray(0, 64))
  })

  it('should throw an exception when trying to use an unsupported hash algorithm', async () => {
    const { hkdf } = createHash('hubba')
    await expect(hkdf(ikm, salt, info)).rejects.toThrow(
      'Unsupported hash algorithm'
    )
  })
})
