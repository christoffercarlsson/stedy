import { createHash, Bytes } from '../../src'

describe('hash', () => {
  const message = Bytes.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const algorithms = [
    {
      algorithm: 'SHA-1',
      digest: Bytes.from([
        10, 77, 85, 168, 215, 120, 229, 2, 47, 171, 112, 25, 119, 197, 216, 64,
        187, 196, 134, 208
      ])
    },
    {
      algorithm: 'SHA-256',
      digest: Bytes.from([
        165, 145, 166, 212, 11, 244, 32, 64, 74, 1, 23, 51, 207, 183, 177, 144,
        214, 44, 101, 191, 11, 205, 163, 43, 87, 178, 119, 217, 173, 159, 20,
        110
      ])
    },
    {
      algorithm: 'SHA-384',
      digest: Bytes.from([
        153, 81, 67, 41, 24, 107, 47, 106, 228, 161, 50, 158, 126, 230, 198, 16,
        167, 41, 99, 99, 53, 23, 74, 198, 183, 64, 249, 2, 131, 150, 252, 200,
        3, 208, 233, 56, 99, 167, 195, 217, 15, 134, 190, 238, 120, 47, 79, 63
      ])
    },
    {
      algorithm: 'SHA-512',
      iterations: 2,
      digest: Bytes.from([
        178, 107, 153, 205, 206, 56, 177, 180, 112, 249, 146, 151, 172, 34, 156,
        221, 152, 188, 173, 123, 63, 187, 157, 4, 180, 22, 245, 144, 230, 92,
        210, 253, 225, 168, 103, 11, 102, 252, 112, 116, 5, 0, 227, 125, 97, 84,
        0, 158, 40, 158, 221, 142, 150, 82, 152, 225, 23, 168, 118, 10, 242, 8,
        55, 49
      ])
    }
  ]

  algorithms.forEach(({ algorithm, digest, iterations }) => {
    it(`should produce the ${algorithm} digest of a given message`, async () => {
      const { hash } = createHash(algorithm)
      expect(await hash(message, iterations)).toEqual(digest)
    })
  })

  it('should throw an exception when trying to use an unsupported hash algorithm', async () => {
    const { hash } = createHash('hubba')
    await expect(hash(message)).rejects.toThrow('Unsupported hash algorithm')
  })
})
