import { createFrom } from '../bytes'
import { ALGORITHM_ECDSA, CURVE_CURVE25519 } from './constants'
import { signMessage } from './curve25519'
import {
  ensureSupportedHash,
  identifyCurve,
  importSignPrivateKey,
  removeKeyPrefix,
  WebCrypto
} from './utils'

const signCurve25519 = (privateKey: Uint8Array, message: Uint8Array) =>
  signMessage(message, removeKeyPrefix(privateKey))

const signECDSA = async (
  crypto: WebCrypto,
  curve: string,
  privateKey: Uint8Array,
  message: Uint8Array,
  hash: string
) =>
  createFrom(
    await crypto.subtle.sign(
      { name: ALGORITHM_ECDSA, hash: await ensureSupportedHash(hash) },
      await importSignPrivateKey(crypto, curve, privateKey),
      message
    )
  )

const sign = async (
  crypto: WebCrypto,
  privateKey: BufferSource,
  message: BufferSource,
  hash?: string
) => {
  const key = createFrom(privateKey)
  const curve = await identifyCurve(key)
  const msg = createFrom(message)
  return curve === CURVE_CURVE25519
    ? signCurve25519(key, msg)
    : signECDSA(crypto, curve, key, msg, hash)
}

export default sign
