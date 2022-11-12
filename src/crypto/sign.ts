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

const signCurve25519 = (message: Uint8Array, privateKey: Uint8Array) =>
  signMessage(message, removeKeyPrefix(privateKey))

const signECDSA = async (
  crypto: WebCrypto,
  curve: string,
  message: Uint8Array,
  privateKey: Uint8Array,
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
  message: BufferSource,
  privateKey: BufferSource,
  hash?: string
) => {
  const key = createFrom(privateKey)
  const curve = await identifyCurve(key)
  const msg = createFrom(message)
  return curve === CURVE_CURVE25519
    ? signCurve25519(msg, key)
    : signECDSA(crypto, curve, msg, key, hash)
}

export default sign
