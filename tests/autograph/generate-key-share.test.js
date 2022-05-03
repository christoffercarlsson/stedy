import { describe, expect, it } from '../../dist/test.js'
import { concat } from '../../dist/chunk.js'
import { generateKeyPair, generateKeyShare } from '../../dist/autograph.js'

export default describe('generateKeyShare', () =>
  it('should generate a key share', async () => {
    const { publicKey: ourIdentityPublicKey } = await generateKeyPair()
    const [keyShare, { publicKey, privateKey }] = await generateKeyShare(
      ourIdentityPublicKey
    )
    expect(keyShare.byteLength).toBe(64)
    expect(publicKey.byteLength).toBe(32)
    expect(privateKey.byteLength).toBe(32)
    expect(keyShare).toEqual(concat([ourIdentityPublicKey, publicKey]))
  }))
