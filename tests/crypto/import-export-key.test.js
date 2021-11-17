import { describe, it, expect } from '../../src/test.js'
import {
  exportKey,
  generateKeyPair,
  generateSignKeyPair,
  importKey
} from '../../src/crypto.js'

export default describe('import/export-key', () => {
  const curves = ['P-256', 'P-384', 'P-521', 'Curve448', 'Curve25519']

  return curves
    .map((curve) => [
      it(`should export and import a raw ${curve} key`, async () => {
        const { publicKey, privateKey } = await generateKeyPair(curve)
        const rawPublicKey = await exportKey(publicKey)
        const rawPrivateKey = await exportKey(privateKey)
        expect(await importKey(curve, false, true, rawPublicKey)).toEqual(
          publicKey
        )
        expect(await importKey(curve, false, false, rawPrivateKey)).toEqual(
          privateKey
        )
      }),

      it(`should export and import a raw ${curve} signing key`, async () => {
        const { publicKey, privateKey } = await generateSignKeyPair(curve)
        const rawPublicKey = await exportKey(publicKey)
        const rawPrivateKey = await exportKey(privateKey)
        expect(await importKey(curve, true, true, rawPublicKey)).toEqual(
          publicKey
        )
        expect(await importKey(curve, true, false, rawPrivateKey)).toEqual(
          privateKey
        )
      })
    ])
    .flat()
})
