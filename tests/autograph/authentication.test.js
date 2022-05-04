import { describe, it, expect } from '../../dist/test.js'
import { concat, createFrom } from '../../dist/chunk.js'
import {
  KEY_CONTEXT_RESPONDER,
  createCertificate,
  createSigningFunction,
  createTrustedParties,
  deriveSharedSecret,
  generateKeyPair,
  generateKeyShare,
  identify,
  sign,
  verify,
  verifySignature,
  authenticate
} from '../../dist/autograph.js'
import { signData } from '../../dist/autograph/utils.js'

export default describe('authentication', async () => {
  const aliceIdentity = await generateKeyPair()
  const bobIdentity = await generateKeyPair()
  const charlieIdentity = await generateKeyPair()
  const data = createFrom('Hello World')
  const certificate = createCertificate([
    [
      charlieIdentity.publicKey,
      await signData(
        createSigningFunction(charlieIdentity.privateKey),
        concat([data, aliceIdentity.publicKey])
      )
    ]
  ])
  return [
    it('should allow Bob and Charlie to establish trust', async () => {
      const [bobKeyShare, bobEphemeralPrivateKey] = await generateKeyShare(
        bobIdentity.publicKey
      )
      const [charlieKeyShare, charlieEphemeralPrivateKey] =
        await generateKeyShare(charlieIdentity.publicKey)
      const bobSharedSecret = await deriveSharedSecret(
        charlieKeyShare,
        bobEphemeralPrivateKey
      )
      const bobAuthentication = await identify(
        createSigningFunction(bobIdentity.privateKey),
        createFrom(),
        bobSharedSecret,
        bobKeyShare,
        charlieKeyShare
      )
      const charlieSharedSecret = await deriveSharedSecret(
        bobKeyShare,
        charlieEphemeralPrivateKey
      )
      const bobVerification = await verify(
        0,
        createTrustedParties(),
        charlieSharedSecret,
        charlieKeyShare,
        bobKeyShare,
        bobAuthentication
      )
      const charlieAuthentication = await identify(
        createSigningFunction(charlieIdentity.privateKey),
        createFrom(),
        charlieSharedSecret,
        charlieKeyShare,
        bobKeyShare,
        KEY_CONTEXT_RESPONDER
      )
      const charlieVerification = await verify(
        0,
        createTrustedParties(),
        bobSharedSecret,
        bobKeyShare,
        charlieKeyShare,
        charlieAuthentication,
        KEY_CONTEXT_RESPONDER
      )
      expect(bobVerification.verified).toBe(true)
      expect(bobVerification.identityKey).toEqual(bobIdentity.publicKey)
      expect(charlieVerification.verified).toBe(true)
      expect(charlieVerification.identityKey).toEqual(charlieIdentity.publicKey)
    }),

    it("should allow Charlie to certify Alice's ownership of her identity key and data", async () => {
      const [aliceKeyShare, aliceEphemeralPrivateKey] = await generateKeyShare(
        aliceIdentity.publicKey
      )
      const [charlieKeyShare, charlieEphemeralPrivateKey] =
        await generateKeyShare(charlieIdentity.publicKey)
      const aliceSharedSecret = await deriveSharedSecret(
        charlieKeyShare,
        aliceEphemeralPrivateKey
      )
      const aliceAuthentication = await authenticate(
        createSigningFunction(aliceIdentity.privateKey),
        data,
        createFrom(),
        aliceSharedSecret,
        aliceKeyShare,
        charlieKeyShare
      )
      const charlieSharedSecret = await deriveSharedSecret(
        aliceKeyShare,
        charlieEphemeralPrivateKey
      )
      const aliceVerification = await verify(
        0,
        createTrustedParties(),
        charlieSharedSecret,
        charlieKeyShare,
        aliceKeyShare,
        aliceAuthentication
      )
      const charlieAuthentication = await sign(
        createSigningFunction(charlieIdentity.privateKey),
        createFrom(),
        charlieSharedSecret,
        charlieKeyShare,
        aliceKeyShare,
        data
      )
      const charlieVerification = await verifySignature(
        0,
        createTrustedParties(),
        data,
        aliceSharedSecret,
        aliceKeyShare,
        charlieKeyShare,
        charlieAuthentication
      )
      expect(aliceVerification.verified).toBe(true)
      expect(aliceVerification.identityKey).toEqual(aliceIdentity.publicKey)
      expect(aliceVerification.data).toEqual(data)
      expect(charlieVerification.verified).toBe(true)
      expect(charlieVerification.identityKey).toEqual(charlieIdentity.publicKey)
      expect(
        concat([charlieVerification.identityKey, charlieVerification.signature])
      ).toEqual(certificate)
    }),

    it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", async () => {
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
      const aliceAuthentication = await authenticate(
        createSigningFunction(aliceIdentity.privateKey),
        data,
        certificate,
        aliceSharedSecret,
        aliceKeyShare,
        bobKeyShare
      )
      const bobSharedSecret = await deriveSharedSecret(
        aliceKeyShare,
        bobEphemeralPrivateKey
      )
      const aliceVerification = await verify(
        1,
        charlieIdentity.publicKey,
        bobSharedSecret,
        bobKeyShare,
        aliceKeyShare,
        aliceAuthentication
      )
      expect(aliceVerification.verified).toBe(true)
      expect(aliceVerification.identityKey).toEqual(aliceIdentity.publicKey)
      expect(aliceVerification.data).toEqual(data)
    })
  ]
})
