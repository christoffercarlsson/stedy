import { describe, it, expect } from '../../src/test.js'
import { generateSignKeyPair } from '../../src/crypto.js'

export default describe('generateSignKeyPair', () => {
  const curves = new Map([
    ['Curve25519', { publicKey: 44, privateKey: 48 }],
    ['P-256', { publicKey: 91, privateKey: 138 }],
    ['P-384', { publicKey: 120, privateKey: 185 }],
    ['P-521', { publicKey: 158, privateKey: 241 }]
  ])

  const tests = [...curves].map(([curve, sizes]) =>
    it(`should generate a signing key pair for ${curve}`, async () => {
      const { publicKey, privateKey } = await generateSignKeyPair(curve)
      expect(publicKey).toBeInstanceOf(Uint8Array)
      expect(publicKey.byteLength).toBe(sizes.publicKey)
      expect(privateKey).toBeInstanceOf(Uint8Array)
      expect(privateKey.byteLength).toBe(sizes.privateKey)
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
