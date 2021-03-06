import { describe, it, expect } from '../../dist/test.js'
import { hash } from '../../dist/crypto.js'

export default describe('hash', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const algorithms = new Map([
    [
      'SHA-256',
      {
        digest: Uint8Array.from([
          165, 145, 166, 212, 11, 244, 32, 64, 74, 1, 23, 51, 207, 183, 177,
          144, 214, 44, 101, 191, 11, 205, 163, 43, 87, 178, 119, 217, 173, 159,
          20, 110
        ])
      }
    ],
    [
      'SHA-384',
      {
        digest: Uint8Array.from([
          153, 81, 67, 41, 24, 107, 47, 106, 228, 161, 50, 158, 126, 230, 198,
          16, 167, 41, 99, 99, 53, 23, 74, 198, 183, 64, 249, 2, 131, 150, 252,
          200, 3, 208, 233, 56, 99, 167, 195, 217, 15, 134, 190, 238, 120, 47,
          79, 63
        ])
      }
    ],
    [
      'SHA-512',
      {
        iterations: 2,
        digest: Uint8Array.from([
          178, 107, 153, 205, 206, 56, 177, 180, 112, 249, 146, 151, 172, 34,
          156, 221, 152, 188, 173, 123, 63, 187, 157, 4, 180, 22, 245, 144, 230,
          92, 210, 253, 225, 168, 103, 11, 102, 252, 112, 116, 5, 0, 227, 125,
          97, 84, 0, 158, 40, 158, 221, 142, 150, 82, 152, 225, 23, 168, 118,
          10, 242, 8, 55, 49
        ])
      }
    ]
  ])

  const tests = [...algorithms].map(([algorithm, { digest, iterations }]) =>
    it(`should produce the ${algorithm} digest of a given message`, async () => {
      expect(await hash(algorithm, message, iterations)).toEqual(digest)
    })
  )

  return tests.concat(
    it('should throw an exception when trying to use an unsupported hash algorithm', async () => {
      await expect(hash('hubba', message)).toReject(
        'Unsupported hash algorithm'
      )
    })
  )
})
