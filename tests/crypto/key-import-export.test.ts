import { createCurve, exportKey } from '../../src'
import { Bytes } from '../../src/bytes'

describe('key import/export', () => {
  const curves = ['P-256', 'P-384', 'P-521', 'Curve25519']

  curves.forEach((curve) => {
    it(`should export and import a raw ${curve} key`, async () => {
      const { generateKeyPair, importKey } = createCurve(curve)
      const { publicKey, privateKey } = await generateKeyPair()
      const rawPublicKey = await exportKey(publicKey)
      const rawPrivateKey = await exportKey(privateKey)
      expect(await importKey(rawPublicKey, false, true)).toEqual(publicKey)
      expect(await importKey(rawPrivateKey, false, false)).toEqual(privateKey)
    })

    it(`should export and import a raw ${curve} signing key`, async () => {
      const { generateSignKeyPair, importKey } = createCurve(curve)
      const { publicKey, privateKey } = await generateSignKeyPair()
      const rawPublicKey = await exportKey(publicKey)
      const rawPrivateKey = await exportKey(privateKey)
      expect(await importKey(rawPublicKey, true, true)).toEqual(publicKey)
      expect(await importKey(rawPrivateKey, true, false)).toEqual(privateKey)
    })
  })

  it(`should throw an exception when trying to export an unsupported key`, async () => {
    const publicKey = Bytes.from([
      48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0, 216, 207, 170, 149, 213, 82,
      215, 160, 39, 171, 128, 33, 39, 213, 87, 222, 119, 150, 96, 114, 232, 56,
      81, 114, 72, 205, 126, 34, 38, 25, 75, 94
    ])
    await expect(exportKey(publicKey.subarray(2))).rejects.toThrow(
      'Unsupported key'
    )
  })

  it(`should throw an exception when trying to import a key for an unsupported elliptic curve`, async () => {
    const { importKey } = createCurve('hubba')
    const rawPublicKey = Bytes.from([
      216, 207, 170, 149, 213, 82, 215, 160, 39, 171, 128, 33, 39, 213, 87, 222,
      119, 150, 96, 114, 232, 56, 81, 114, 72, 205, 126, 34, 38, 25, 75, 94
    ])
    await expect(importKey(rawPublicKey, true, true)).rejects.toThrow(
      'Unsupported elliptic curve'
    )
  })
})
