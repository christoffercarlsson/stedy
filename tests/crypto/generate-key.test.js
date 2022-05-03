import { describe, it, expect } from '../../dist/test.js'
import { generateKey } from '../../dist/crypto.js'

export default describe('generateKey', () => {
  const keySizes = [
    ['AES-128-GCM', 16],
    ['AES-256-GCM', 32]
  ]

  const tests = keySizes.map(([cipher, keySize]) =>
    it(`should generate a symmetric key of size ${keySize} for use with ${cipher}`, async () => {
      const key = await generateKey(cipher)
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.byteLength).toEqual(keySize)
    })
  )

  return tests.concat(
    it('should throw an exception when trying to generate a key for an unsupported cipher', async () => {
      await expect(generateKey('AES-CBC')).toReject('Unsupported cipher')
    })
  )
})
