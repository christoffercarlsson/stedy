import { describe, it, expect } from '../../dist/test.js'
import { generateSignKeyPair, sign, verify } from '../../dist/crypto.js'

export default describe('sign/verify', () => {
  const message = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])
  const curves = ['P-256', 'P-384', 'P-521']
  const hashes = ['SHA-256', 'SHA-384', 'SHA-512']

  const tests = curves
    .map((curve) =>
      hashes.map((hash) =>
        it(`should sign a given message using ECDSA with ${curve} and ${hash}`, async () => {
          const { publicKey, privateKey } = await generateSignKeyPair(curve)
          const signature = await sign(message, privateKey, hash)
          expect(await verify(message, publicKey, signature, hash)).toBe(true)
        })
      )
    )
    .flat()

  return tests.concat(
    ['Curve448', 'Curve25519'].map((curve) =>
      it(`should sign a given message using EdDSA with ${curve}`, async () => {
        const { publicKey, privateKey } = await generateSignKeyPair(curve)
        const signature = await sign(message, privateKey)
        expect(await verify(message, publicKey, signature)).toBe(true)
      })
    )
  )
})
