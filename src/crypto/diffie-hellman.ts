import { createFrom } from '../bytes'
import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  SHARED_SECRET_DEFAULT_SIZE
} from './constants'
import { scalarMult } from './curve25519'
import {
  identifyCurve,
  importPrivateKey,
  importPublicKey,
  removeKeyPrefix,
  WebCrypto
} from './utils'

const deriveCurve25519 = (
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  size: number
) =>
  scalarMult(removeKeyPrefix(privateKey), removeKeyPrefix(publicKey)).subarray(
    0,
    size
  )

const deriveECDH = async (
  crypto: WebCrypto,
  curve: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  size: number
) =>
  createFrom(
    await crypto.subtle.deriveBits(
      {
        name: ALGORITHM_ECDH,
        public: await importPublicKey(crypto, curve, publicKey)
      },
      await importPrivateKey(crypto, curve, privateKey),
      size * 8
    )
  )

const diffieHellman = async (
  crypto: WebCrypto,
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource,
  size?: number
) => {
  const privateKey = createFrom(ourPrivateKey)
  const publicKey = createFrom(theirPublicKey)
  const outputSize =
    Number.isInteger(size) && size > 0 ? size : SHARED_SECRET_DEFAULT_SIZE
  const curve = await identifyCurve(privateKey)
  return curve === CURVE_CURVE25519
    ? deriveCurve25519(privateKey, publicKey, outputSize)
    : deriveECDH(crypto, curve, privateKey, publicKey, outputSize)
}

export default diffieHellman
