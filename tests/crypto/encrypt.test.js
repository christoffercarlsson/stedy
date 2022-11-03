import { describe, it, expect } from '../../src/test.js'
import { encrypt } from '../../src/crypto.js'

export default describe('encrypt', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const ciphers = new Map([
    [
      'AES-128-GCM',
      {
        key: Uint8Array.from([
          185, 80, 138, 12, 247, 136, 235, 60, 80, 60, 241, 12, 23, 121, 61, 114
        ]),
        nonce: Uint8Array.from([
          117, 46, 245, 124, 66, 4, 198, 118, 187, 78, 18, 169
        ]),
        ciphertext: Uint8Array.from([
          190, 93, 32, 212, 130, 193, 34, 170, 109, 219, 15, 43, 226, 223, 22,
          84, 64, 89, 253, 159, 8, 33, 214, 189, 27, 248, 228
        ]),
        additionalData: Uint8Array.from([4, 3, 2, 1])
      }
    ],
    [
      'AES-256-GCM',
      {
        key: Uint8Array.from([
          108, 111, 106, 27, 235, 68, 78, 52, 212, 131, 174, 205, 30, 68, 235,
          244, 135, 32, 242, 198, 103, 85, 112, 50, 240, 104, 45, 83, 162, 109,
          30, 48
        ]),
        nonce: Uint8Array.from([
          219, 45, 62, 208, 201, 18, 57, 1, 200, 223, 7, 137
        ]),
        ciphertext: Uint8Array.from([
          219, 10, 241, 174, 76, 151, 208, 220, 89, 31, 85, 44, 99, 39, 187,
          231, 120, 231, 67, 101, 50, 187, 148, 250, 16, 3, 190
        ]),
        additionalData: Uint8Array.from([1, 2, 3, 4])
      }
    ]
  ])

  const tests = [...ciphers]
    .map(([cipher, { key, nonce, ciphertext, additionalData }]) => [
      it(`should encrypt using ${cipher}`, async () => {
        expect(
          await encrypt(cipher, key, nonce, message, additionalData)
        ).toEqual(ciphertext)
      }),

      it(`should throw an exception for invalid ${cipher} keys`, async () => {
        await expect(
          encrypt(
            cipher,
            key.subarray(0, key.byteLength - 2),
            nonce,
            message,
            additionalData
          )
        ).toReject('Invalid key size')
      }),

      it(`should throw an exception for invalid ${cipher} nonces`, async () => {
        await expect(
          encrypt(
            cipher,
            key,
            nonce.subarray(0, nonce.byteLength - 2),
            message,
            additionalData
          )
        ).toReject('Invalid nonce size')
      })
    ])
    .flat()

  return tests.concat(
    it('should throw an exception for unsupported ciphers', async () => {
      const { key, nonce } = ciphers.get('AES-256-GCM')
      await expect(encrypt('hubba', key, nonce, message)).toReject(
        'Unsupported cipher'
      )
    })
  )
})
