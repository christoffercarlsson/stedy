import { createHash } from '../../src'

describe('pbkdf2', () => {
  const password = Uint8Array.from([
    99, 111, 114, 114, 101, 99, 116, 104, 111, 114, 115, 101, 98, 97, 116, 116,
    101, 114, 121, 115, 116, 97, 112, 108, 101
  ])
  const salt = Uint8Array.from([
    181, 22, 123, 170, 54, 160, 197, 195, 99, 130, 109, 36, 7, 46, 187, 141
  ])
  const iterations = 10000
  const hashes = [
    {
      algorithm: 'SHA-256',
      key: Uint8Array.from([
        246, 218, 7, 160, 8, 64, 130, 244, 215, 249, 39, 67, 144, 142, 188, 155,
        41, 148, 195, 60, 200, 30, 135, 247, 7, 207, 3, 85, 89, 236, 204, 150
      ])
    },
    {
      algorithm: 'SHA-384',
      key: Uint8Array.from([
        42, 228, 95, 255, 142, 166, 137, 247, 58, 210, 173, 17, 187, 88, 129,
        95, 237, 221, 108, 144, 191, 43, 19, 32, 86, 83, 167, 84, 1, 37, 1, 112,
        145, 150, 221, 4, 220, 73, 210, 225, 157, 160, 91, 175, 143, 232, 29,
        228
      ])
    },
    {
      algorithm: 'SHA-512',
      key: Uint8Array.from([
        131, 62, 130, 158, 244, 216, 98, 98, 206, 91, 199, 236, 183, 170, 94,
        106, 241, 173, 205, 188, 199, 76, 69, 191, 181, 33, 88, 88, 3, 116, 12,
        197, 129, 192, 238, 159, 199, 75, 77, 14, 219, 45, 242, 94, 149, 224,
        222, 235, 25, 21, 175, 111, 138, 226, 69, 70, 232, 23, 144, 206, 172,
        53, 189, 81
      ])
    }
  ]

  hashes.forEach(({ algorithm, key }) => {
    const { pbkdf2 } = createHash(algorithm)

    it(`should derive new a key using PBKDF2 with ${algorithm}`, async () => {
      expect(await pbkdf2(password, salt, iterations, key.byteLength)).toEqual(
        key
      )
    })

    it('should derive a key with the size of the given hash function when the last two arguments are omitted', async () => {
      expect(await pbkdf2(password, salt)).toEqual(key.subarray(0, 64))
    })
  })

  it('should throw an exception when trying to use an unsupported hash algorithm', async () => {
    const { pbkdf2 } = createHash('hubba')
    await expect(pbkdf2(password, salt, iterations)).rejects.toThrow(
      'Unsupported hash algorithm'
    )
  })
})
