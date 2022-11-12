import { createFrom } from '../bytes'
import {
  ALGORITHM_ECDSA,
  CURVE25519_SIGNATURE_SIZE,
  CURVE_CURVE25519
} from './constants'
import { verifyMessage } from './curve25519'
import {
  ensureSupportedHash,
  identifyCurve,
  importSignPublicKey,
  removeKeyPrefix,
  WebCrypto
} from './utils'

const isValidSignature = (curve: string, signature: Uint8Array) => {
  switch (curve) {
    case CURVE_CURVE25519:
      return signature.byteLength === CURVE25519_SIGNATURE_SIZE
    default:
      return signature.byteLength > 0
  }
}

const verifyCurve25519 = (
  message: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array
) => verifyMessage(signature, message, removeKeyPrefix(publicKey))

const verifyECDSA = async (
  crypto: WebCrypto,
  curve: string,
  message: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array,
  hash: string
) =>
  crypto.subtle.verify(
    { name: ALGORITHM_ECDSA, hash: await ensureSupportedHash(hash) },
    await importSignPublicKey(crypto, curve, publicKey),
    signature,
    message
  )

const verify = async (
  crypto: WebCrypto,
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource,
  hash?: string
) => {
  const key = createFrom(publicKey)
  const curve = await identifyCurve(key)
  const msg = createFrom(message)
  const sig = createFrom(signature)
  if (!isValidSignature(curve, sig)) {
    return false
  }
  return curve === CURVE_CURVE25519
    ? verifyCurve25519(msg, key, sig)
    : verifyECDSA(crypto, curve, msg, key, sig, hash)
}

export default verify
