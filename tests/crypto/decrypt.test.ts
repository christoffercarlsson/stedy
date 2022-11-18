import { createCipher } from '../../src'
import { Chunk } from '../../src/bytes'

describe('decrypt', () => {
  const message = Chunk.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const ciphers = [
    {
      cipher: 'AES-128-CBC',
      key: Chunk.from([
        237, 75, 94, 1, 53, 119, 181, 12, 56, 235, 235, 136, 250, 76, 85, 165
      ]),
      nonce: Chunk.from([
        47, 237, 161, 185, 170, 224, 140, 50, 2, 195, 169, 178, 107, 153, 33,
        156
      ]),
      ciphertext: Chunk.from([
        28, 255, 236, 139, 107, 95, 99, 76, 209, 148, 120, 168, 149, 147, 248,
        36
      ])
    },
    {
      cipher: 'AES-128-CTR',
      key: Chunk.from([
        237, 75, 94, 1, 53, 119, 181, 12, 56, 235, 235, 136, 250, 76, 85, 165
      ]),
      nonce: Chunk.from([
        47, 237, 161, 185, 170, 224, 140, 50, 2, 195, 169, 178, 107, 153, 33,
        156
      ]),
      ciphertext: Chunk.from([
        134, 44, 226, 224, 31, 197, 83, 33, 252, 136, 104
      ])
    },
    {
      cipher: 'AES-128-GCM',
      key: Chunk.from([
        185, 80, 138, 12, 247, 136, 235, 60, 80, 60, 241, 12, 23, 121, 61, 114
      ]),
      nonce: Chunk.from([117, 46, 245, 124, 66, 4, 198, 118, 187, 78, 18, 169]),
      ciphertext: Chunk.from([
        190, 93, 32, 212, 130, 193, 34, 170, 109, 219, 15, 43, 226, 223, 22, 84,
        64, 89, 253, 159, 8, 33, 214, 189, 27, 248, 228
      ]),
      associatedData: Chunk.from([4, 3, 2, 1])
    },
    {
      cipher: 'AES-192-CBC',
      key: Chunk.from([
        235, 169, 174, 141, 142, 142, 132, 191, 222, 118, 166, 36, 96, 43, 40,
        169, 139, 79, 85, 176, 143, 151, 52, 192
      ]),
      nonce: Chunk.from([
        47, 237, 161, 185, 170, 224, 140, 50, 2, 195, 169, 178, 107, 153, 33,
        156
      ]),
      ciphertext: Chunk.from([
        112, 29, 213, 146, 16, 44, 186, 129, 34, 132, 10, 93, 102, 128, 26, 66
      ])
    },
    {
      cipher: 'AES-192-CTR',
      key: Chunk.from([
        235, 169, 174, 141, 142, 142, 132, 191, 222, 118, 166, 36, 96, 43, 40,
        169, 139, 79, 85, 176, 143, 151, 52, 192
      ]),
      nonce: Chunk.from([
        47, 237, 161, 185, 170, 224, 140, 50, 2, 195, 169, 178, 107, 153, 33,
        156
      ]),
      ciphertext: Chunk.from([
        203, 128, 219, 13, 63, 194, 196, 152, 116, 153, 8
      ])
    },
    {
      cipher: 'AES-192-GCM',
      key: Chunk.from([
        235, 169, 174, 141, 142, 142, 132, 191, 222, 118, 166, 36, 96, 43, 40,
        169, 139, 79, 85, 176, 143, 151, 52, 192
      ]),
      nonce: Chunk.from([117, 46, 245, 124, 66, 4, 198, 118, 187, 78, 18, 169]),
      ciphertext: Chunk.from([
        225, 113, 234, 174, 84, 172, 252, 30, 22, 112, 17, 112, 31, 198, 237, 3,
        25, 228, 147, 253, 104, 239, 118, 235, 166, 205, 228
      ]),
      associatedData: Chunk.from([4, 3, 2, 1])
    },
    {
      cipher: 'AES-256-CBC',
      key: Chunk.from([
        123, 155, 76, 102, 214, 233, 53, 251, 117, 209, 69, 223, 49, 200, 29,
        215, 55, 150, 38, 137, 40, 178, 102, 129, 149, 132, 80, 112, 170, 32,
        232, 239
      ]),
      nonce: Chunk.from([
        157, 120, 53, 216, 87, 175, 156, 207, 163, 229, 105, 113, 142, 120, 236,
        152
      ]),
      ciphertext: Chunk.from([
        166, 88, 33, 133, 41, 110, 141, 164, 99, 240, 165, 156, 143, 162, 137,
        19
      ])
    },
    {
      cipher: 'AES-256-CTR',
      key: Chunk.from([
        123, 155, 76, 102, 214, 233, 53, 251, 117, 209, 69, 223, 49, 200, 29,
        215, 55, 150, 38, 137, 40, 178, 102, 129, 149, 132, 80, 112, 170, 32,
        232, 239
      ]),
      nonce: Chunk.from([
        157, 120, 53, 216, 87, 175, 156, 207, 163, 229, 105, 113, 142, 120, 236,
        152
      ]),
      ciphertext: Chunk.from([3, 97, 43, 249, 197, 124, 46, 247, 57, 34, 204])
    },
    {
      cipher: 'AES-256-GCM',
      key: Chunk.from([
        108, 111, 106, 27, 235, 68, 78, 52, 212, 131, 174, 205, 30, 68, 235,
        244, 135, 32, 242, 198, 103, 85, 112, 50, 240, 104, 45, 83, 162, 109,
        30, 48
      ]),
      nonce: Chunk.from([219, 45, 62, 208, 201, 18, 57, 1, 200, 223, 7, 137]),
      ciphertext: Chunk.from([
        219, 10, 241, 174, 76, 151, 208, 220, 89, 31, 85, 44, 99, 39, 187, 231,
        120, 231, 67, 101, 50, 187, 148, 250, 16, 3, 190
      ]),
      associatedData: Chunk.from([1, 2, 3, 4])
    }
  ]

  ciphers.forEach(({ cipher, key, nonce, ciphertext, associatedData }) => {
    const { decrypt } = createCipher(cipher)

    it(`should decrypt using ${cipher}`, async () => {
      expect(await decrypt(key, nonce, ciphertext, associatedData)).toEqual(
        message
      )
    })

    it(`should throw an exception for invalid ${cipher} keys`, async () => {
      await expect(
        decrypt(
          key.subarray(0, key.byteLength - 2),
          nonce,
          ciphertext,
          associatedData
        )
      ).rejects.toThrow('Invalid key size')
    })

    it(`should throw an exception for invalid ${cipher} nonces`, async () => {
      await expect(
        decrypt(
          key,
          nonce.subarray(0, nonce.byteLength - 2),
          ciphertext,
          associatedData
        )
      ).rejects.toThrow('Invalid nonce size')
    })
  })

  it('should throw an exception for unsupported ciphers', async () => {
    const { decrypt } = createCipher('hubba')
    const { key, nonce, ciphertext } = ciphers[0]
    await expect(decrypt(key, nonce, ciphertext)).rejects.toThrow(
      'Unsupported cipher'
    )
  })
})
