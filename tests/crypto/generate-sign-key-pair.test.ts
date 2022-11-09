import { generateSignKeyPair } from '../../src/crypto'

describe('generateSignKeyPair', () => {
  const curves = [
    { curve: 'Curve25519', publicKeySize: 44, privateKeySize: 48 },
    { curve: 'P-256', publicKeySize: 91, privateKeySize: 138 },
    { curve: 'P-384', publicKeySize: 120, privateKeySize: 185 },
    { curve: 'P-521', publicKeySize: 158, privateKeySize: 241 }
  ]

  curves.forEach(({ curve, publicKeySize, privateKeySize }) => {
    it(`should generate a signing key pair for ${curve}`, async () => {
      const { publicKey, privateKey } = await generateSignKeyPair(curve)
      expect(publicKey).toBeInstanceOf(Uint8Array)
      expect(publicKey.byteLength).toBe(publicKeySize)
      expect(privateKey).toBeInstanceOf(Uint8Array)
      expect(privateKey.byteLength).toBe(privateKeySize)
    })
  })

  it('should throw an exception when trying to generate a signing key pair for an unsupported elliptic curve', async () => {
    await expect(generateSignKeyPair('hubba')).rejects.toThrow(
      'Unsupported elliptic curve'
    )
  })
})
