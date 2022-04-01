import { describe, expect, it } from '../../src/test.js'
import {
  generateKeyPair,
  generateKeyShare,
  deriveSecretKey
} from '../../src/autograph.js'

export default describe('deriveSecretKey', () =>
  it('should derive a shared secret key', async () => {
    const aliceIdentity = await generateKeyPair()
    const bobIdentity = await generateKeyPair()
    const [aliceKeyShare, aliceEphemeral] = await generateKeyShare(
      aliceIdentity.publicKey
    )
    const [bobKeyShare, bobEphemeral] = await generateKeyShare(
      bobIdentity.publicKey
    )
    const aliceSecretKey = await deriveSecretKey(
      bobKeyShare,
      aliceEphemeral.privateKey
    )
    const bobSecretKey = await deriveSecretKey(
      aliceKeyShare,
      bobEphemeral.privateKey
    )
    expect(aliceSecretKey.byteLength).toBe(32)
    expect(aliceSecretKey).toEqual(bobSecretKey)
  }))
