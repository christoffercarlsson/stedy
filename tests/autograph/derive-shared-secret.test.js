import { describe, expect, it } from '../../dist/test.js'
import {
  generateKeyPair,
  generateKeyShare,
  deriveSharedSecret
} from '../../dist/autograph.js'

export default describe('deriveSharedSecret', () =>
  it('should derive a shared secret key', async () => {
    const aliceIdentity = await generateKeyPair()
    const bobIdentity = await generateKeyPair()
    const [aliceKeyShare, aliceEphemeralPrivateKey] = await generateKeyShare(
      aliceIdentity.publicKey
    )
    const [bobKeyShare, bobEphemeralPrivateKey] = await generateKeyShare(
      bobIdentity.publicKey
    )
    const aliceSharedSecret = await deriveSharedSecret(
      bobKeyShare,
      aliceEphemeralPrivateKey
    )
    const bobSharedSecret = await deriveSharedSecret(
      aliceKeyShare,
      bobEphemeralPrivateKey
    )
    expect(aliceSharedSecret.byteLength).toBe(32)
    expect(aliceSharedSecret).toEqual(bobSharedSecret)
  }))
