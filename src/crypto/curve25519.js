import { curve25519, getPublicKey, sign, verify, utils } from '@noble/ed25519'

export const keyPair = () => {
  const privateKey = utils.randomPrivateKey()
  const publicKey = curve25519.scalarMultBase(privateKey)
  return { publicKey, privateKey }
}

export const scalarMult = (privateKey, publicKey) =>
  curve25519.scalarMult(privateKey, publicKey)

export const signKeyPair = async () => {
  const privateKey = utils.randomPrivateKey()
  const publicKey = await getPublicKey(privateKey)
  return { publicKey, privateKey }
}

export const signMessage = (message, privateKey) => sign(message, privateKey)

export const verifyMessage = (signature, message, publicKey) =>
  verify(signature, message, publicKey)
