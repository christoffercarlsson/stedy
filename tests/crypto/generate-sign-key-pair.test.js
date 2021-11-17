import { describe, it, expect } from '../../src/test.js'
import { generateSignKeyPair } from '../../src/crypto.js'

export default describe('generateSignKeyPair', () => {
  const curves = ['P-256', 'P-384', 'P-521', 'Curve448', 'Curve25519']

  const tests = curves.map((curve) =>
    it(`should generate a signing key pair for ${curve}`, async () => {
      const { publicKey, privateKey } = await generateSignKeyPair(curve)
      expect(publicKey).toBeInstanceOf(Uint8Array)
      expect(publicKey.byteLength).toBeGreaterThan(0)
      expect(privateKey).toBeInstanceOf(Uint8Array)
      expect(privateKey.byteLength).toBeGreaterThan(0)
    })
  )

  return tests.concat(
    it('should throw an exception when trying to generate a signing key pair for an unsupported elliptic curve', async () => {
      await expect(generateSignKeyPair('hubba')).toReject(
        'Unsupported elliptic curve'
      )
    })
  )
})
