import {
  CURVE_CURVE25519,
  generateKeyPair as generateKeys,
  generateSignKeyPair as generateSigningKeys
} from '../crypto.js'
import { decodeKeyPair, exportKeyPair } from './utils.js'

export const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateKeys(CURVE_CURVE25519))

export const generateKeyPair = async (encoding) =>
  exportKeyPair(
    decodeKeyPair(await generateSigningKeys(CURVE_CURVE25519), encoding)
  )
