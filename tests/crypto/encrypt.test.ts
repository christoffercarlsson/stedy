import { encrypt } from '../../src/crypto'

describe('encrypt', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const ciphers = [
    {
      cipher: 'AES-128-CBC',
      key: Uint8Array.from([
        237, 75, 94, 1, 53, 119, 181, 12, 56, 235, 235, 136, 250, 76, 85, 165
      ]),
      nonce: Uint8Array.from([
        47, 237, 161, 185, 170, 224, 140, 50, 2, 195, 169, 178, 107, 153, 33,
        156
      ]),
      ciphertext: Uint8Array.from([
        28, 255, 236, 139, 107, 95, 99, 76, 209, 148, 120, 168, 149, 147, 248,
        36
      ])
    },
    {
      cipher: 'AES-128-GCM',
      key: Uint8Array.from([
        185, 80, 138, 12, 247, 136, 235, 60, 80, 60, 241, 12, 23, 121, 61, 114
      ]),
      nonce: Uint8Array.from([
        117, 46, 245, 124, 66, 4, 198, 118, 187, 78, 18, 169
      ]),
      ciphertext: Uint8Array.from([
        190, 93, 32, 212, 130, 193, 34, 170, 109, 219, 15, 43, 226, 223, 22, 84,
        64, 89, 253, 159, 8, 33, 214, 189, 27, 248, 228
      ]),
      associatedData: Uint8Array.from([4, 3, 2, 1])
    },
    {
      cipher: 'AES-256-CBC',
      key: Uint8Array.from([
        123, 155, 76, 102, 214, 233, 53, 251, 117, 209, 69, 223, 49, 200, 29,
        215, 55, 150, 38, 137, 40, 178, 102, 129, 149, 132, 80, 112, 170, 32,
        232, 239
      ]),
      nonce: Uint8Array.from([
        157, 120, 53, 216, 87, 175, 156, 207, 163, 229, 105, 113, 142, 120, 236,
        152
      ]),
      ciphertext: Uint8Array.from([
        166, 88, 33, 133, 41, 110, 141, 164, 99, 240, 165, 156, 143, 162, 137,
        19
      ])
    },
    {
      cipher: 'AES-256-GCM',
      key: Uint8Array.from([
        108, 111, 106, 27, 235, 68, 78, 52, 212, 131, 174, 205, 30, 68, 235,
        244, 135, 32, 242, 198, 103, 85, 112, 50, 240, 104, 45, 83, 162, 109,
        30, 48
      ]),
      nonce: Uint8Array.from([
        219, 45, 62, 208, 201, 18, 57, 1, 200, 223, 7, 137
      ]),
      ciphertext: Uint8Array.from([
        219, 10, 241, 174, 76, 151, 208, 220, 89, 31, 85, 44, 99, 39, 187, 231,
        120, 231, 67, 101, 50, 187, 148, 250, 16, 3, 190
      ]),
      associatedData: Uint8Array.from([1, 2, 3, 4])
    }
  ]

  ciphers.forEach(({ cipher, key, nonce, ciphertext, associatedData }) => {
    it(`should encrypt using ${cipher}`, async () => {
      expect(
        await encrypt(cipher, key, nonce, message, associatedData)
      ).toEqual(ciphertext)
    })

    it(`should throw an exception for invalid ${cipher} keys`, async () => {
      await expect(
        encrypt(
          cipher,
          key.subarray(0, key.byteLength - 2),
          nonce,
          message,
          associatedData
        )
      ).rejects.toThrow('Invalid key size')
    })

    it(`should throw an exception for invalid ${cipher} nonces`, async () => {
      await expect(
        encrypt(
          cipher,
          key,
          nonce.subarray(0, nonce.byteLength - 2),
          message,
          associatedData
        )
      ).rejects.toThrow('Invalid nonce size')
    })
  })

  it('should throw an exception for unsupported ciphers', async () => {
    const { key, nonce } = ciphers[1]
    await expect(encrypt('hubba', key, nonce, message)).rejects.toThrow(
      'Unsupported cipher'
    )
  })
})
