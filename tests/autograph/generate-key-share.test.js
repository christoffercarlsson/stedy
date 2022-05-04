import { describe, expect, it } from '../../dist/test.js'
import { startsWith } from '../../dist/chunk.js'
import { generateKeyPair, generateKeyShare } from '../../dist/autograph.js'

export default describe('generateKeyShare', () =>
  it('should generate a key share', async () => {
    const { publicKey: ourIdentityPublicKey } = await generateKeyPair()
    const [keyShare, ourEphemeralPrivateKey] = await generateKeyShare(
      ourIdentityPublicKey
    )
    expect(keyShare.byteLength).toBe(64)
    expect(ourEphemeralPrivateKey.byteLength).toBe(32)
    expect(startsWith(keyShare, ourIdentityPublicKey)).toBe(true)
  }))
