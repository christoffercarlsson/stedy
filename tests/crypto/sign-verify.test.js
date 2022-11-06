import { generateSignKeyPair, sign, verify } from '../../src/crypto'

describe('sign/verify', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const curves = ['P-256', 'P-384', 'P-521']
  const hashes = ['SHA-256', 'SHA-384', 'SHA-512']

  curves.forEach((curve) => {
    hashes.forEach((hash) => {
      it(`should sign a given message using ECDSA with ${curve} and ${hash}`, async () => {
        const { publicKey, privateKey } = await generateSignKeyPair(curve)
        const signature = await sign(message, privateKey, hash)
        expect(await verify(message, publicKey, signature, hash)).toBe(true)
      })
    })
  })

  it('should sign a given message using EdDSA with Curve25519', async () => {
    const { publicKey, privateKey } = await generateSignKeyPair('Curve25519')
    const signature = await sign(message, privateKey)
    expect(await verify(message, publicKey, signature)).toBe(true)
  })
})
