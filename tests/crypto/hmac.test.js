import { describe, it, expect } from '../../dist/test.js'
import { hmac } from '../../dist/crypto.js'

export default describe('hmac', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const key = Uint8Array.from([
    84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 101, 99, 114, 101, 116
  ])
  const algorithms = new Map([
    [
      'SHA-256',
      Uint8Array.from([
        234, 255, 249, 237, 0, 148, 11, 229, 219, 130, 86, 17, 38, 0, 148, 77,
        35, 230, 7, 243, 61, 44, 216, 177, 110, 23, 111, 253, 178, 182, 103, 202
      ])
    ],
    [
      'SHA-384',
      Uint8Array.from([
        74, 30, 114, 194, 183, 160, 113, 9, 28, 132, 141, 29, 86, 11, 199, 110,
        172, 57, 201, 12, 8, 160, 19, 232, 145, 163, 227, 174, 126, 201, 15,
        195, 254, 60, 56, 179, 31, 106, 43, 164, 247, 217, 125, 237, 71, 229,
        188, 59
      ])
    ],
    [
      'SHA-512',
      Uint8Array.from([
        40, 204, 18, 236, 71, 245, 5, 78, 9, 105, 27, 87, 100, 182, 93, 134,
        246, 15, 99, 228, 239, 217, 211, 65, 122, 169, 203, 57, 207, 155, 59,
        195, 25, 23, 110, 118, 135, 181, 52, 14, 35, 181, 216, 59, 2, 26, 207,
        231, 176, 181, 80, 150, 179, 203, 121, 224, 190, 22, 156, 214, 166, 255,
        27, 205
      ])
    ]
  ])

  const tests = [...algorithms].map(([algorithm, signature]) =>
    it(`should compute the HMAC digest of a message using ${algorithm} with a given key`, async () => {
      expect(await hmac(algorithm, key, message)).toEqual(signature)
    })
  )

  return tests.concat(
    it('should throw an exception when trying to use an unsupported hash algorithm', async () => {
      await expect(hmac('hubba', key, message)).toReject(
        'Unsupported hash algorithm'
      )
    })
  )
})
