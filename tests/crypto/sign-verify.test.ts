import { createCurve } from '../../src'
import { Bytes } from '../../src/bytes'

describe('sign/verify', () => {
  const message = Bytes.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const curves = ['P-256', 'P-384', 'P-521']
  const hashes = ['SHA-256', 'SHA-384', 'SHA-512']

  curves.forEach((curve) => {
    hashes.forEach((hash) => {
      it(`should sign a given message using ECDSA with ${curve} and ${hash}`, async () => {
        const { generateSignKeyPair, sign, verify } = createCurve(curve, hash)
        const { publicKey, privateKey } = await generateSignKeyPair()
        const signature = await sign(privateKey, message)
        expect(await verify(message, publicKey, signature)).toBe(true)
      })
    })
  })

  it('should sign a given message using EdDSA with Curve25519', async () => {
    const { generateSignKeyPair, sign, verify } = createCurve('Curve25519')
    const { publicKey, privateKey } = await generateSignKeyPair()
    const signature = await sign(privateKey, message)
    expect(await verify(message, publicKey, signature)).toBe(true)
  })

  it('should not verify invalid signatures using EdDSA with Curve25519', async () => {
    const { generateSignKeyPair, sign, verify } = createCurve('Curve25519')
    const { publicKey, privateKey } = await generateSignKeyPair()
    const signature = await sign(privateKey, message)
    expect(await verify(message, publicKey, signature.subarray(0, 62))).toBe(
      false
    )
  })
})
