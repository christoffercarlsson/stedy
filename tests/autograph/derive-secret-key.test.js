import { describe, it, expect } from '../../dist/test.js'
import { createFrom } from '../../dist/chunk.js'
import {
  KEY_CONTEXT_INITIATOR,
  KEY_CONTEXT_RESPONDER,
  authenticate,
  createSigningFunction,
  deriveSecretKey,
  deriveSharedSecret,
  generateEphemeralKeyPair,
  generateKeyPair,
  generateKeyShare
} from '../../dist/autograph.js'

export default describe('deriveSecretKey', async () =>
  it('should allow Bob and Alice derive a shared secret key', async () => {
    const aliceIdentity = await generateKeyPair()
    const bobIdentity = await generateKeyPair()
    const aliceEphemeral = await generateEphemeralKeyPair()
    const bobEphemeral = await generateEphemeralKeyPair()
    const [aliceKeyShare, aliceSessionPrivateKey] = await generateKeyShare(
      aliceIdentity.publicKey
    )
    const [bobKeyShare, bobSessionPrivateKey] = await generateKeyShare(
      bobIdentity.publicKey
    )
    const aliceSharedSecret = await deriveSharedSecret(
      bobKeyShare,
      aliceSessionPrivateKey
    )
    const aliceAuthentication = await authenticate(
      createSigningFunction(aliceIdentity.privateKey),
      aliceEphemeral.publicKey,
      createFrom(),
      aliceSharedSecret,
      aliceKeyShare,
      bobKeyShare
    )
    const bobSharedSecret = await deriveSharedSecret(
      aliceKeyShare,
      bobSessionPrivateKey
    )
    const aliceVerification = await deriveSecretKey(
      0,
      createFrom(),
      bobEphemeral.privateKey,
      bobSharedSecret,
      bobKeyShare,
      aliceKeyShare,
      aliceAuthentication,
      KEY_CONTEXT_INITIATOR
    )
    const bobAuthentication = await authenticate(
      createSigningFunction(bobIdentity.privateKey),
      bobEphemeral.publicKey,
      createFrom(),
      bobSharedSecret,
      bobKeyShare,
      aliceKeyShare,
      KEY_CONTEXT_RESPONDER
    )
    const bobVerification = await deriveSecretKey(
      0,
      createFrom(),
      aliceEphemeral.privateKey,
      aliceSharedSecret,
      aliceKeyShare,
      bobKeyShare,
      bobAuthentication,
      KEY_CONTEXT_RESPONDER
    )
    expect(aliceVerification.verified).toBe(true)
    expect(bobVerification.verified).toBe(true)
    expect(aliceVerification.identityKey).toEqual(aliceIdentity.publicKey)
    expect(bobVerification.identityKey).toEqual(bobIdentity.publicKey)
    expect(aliceVerification.secretKey.byteLength).toBe(32)
    expect(aliceVerification.secretKey).toEqual(bobVerification.secretKey)
  }))
