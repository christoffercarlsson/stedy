import { curve25519, getPublicKey, sign, verify, utils } from '@noble/ed25519'

export const keyPair = () => {
  const privateKey = utils.randomPrivateKey()
  const publicKey = curve25519.scalarMultBase(privateKey)
  return { publicKey, privateKey }
}

export const scalarMult = (privateKey: Uint8Array, publicKey: Uint8Array) =>
  curve25519.scalarMult(privateKey, publicKey)

export const signKeyPair = async () => {
  const privateKey = utils.randomPrivateKey()
  const publicKey = await getPublicKey(privateKey)
  return { publicKey, privateKey }
}

export const signMessage = (message: Uint8Array, privateKey: Uint8Array) =>
  sign(message, privateKey)

export const verifyMessage = (
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
) => verify(signature, message, publicKey)
