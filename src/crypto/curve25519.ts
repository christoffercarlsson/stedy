import { ed25519, x25519 } from '@noble/curves/ed25519'

export const keyPair = () => {
  const privateKey = x25519.utils.randomPrivateKey()
  const publicKey = x25519.scalarMultBase(privateKey)
  return { publicKey, privateKey }
}

export const scalarMult = (privateKey: Uint8Array, publicKey: Uint8Array) =>
  x25519.scalarMult(privateKey, publicKey)

export const signKeyPair = () => {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = ed25519.getPublicKey(privateKey)
  return { publicKey, privateKey }
}

export const signMessage = (message: Uint8Array, privateKey: Uint8Array) =>
  ed25519.sign(message, privateKey)

export const verifyMessage = (
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
) => ed25519.verify(signature, message, publicKey)
