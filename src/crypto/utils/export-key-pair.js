import { createFrom } from '../../chunk.js'
import { KEY_FORMAT_PKCS8, KEY_FORMAT_SPKI } from '../constants.js'

const exportKey = async (crypto, format, key) =>
  createFrom(await crypto.subtle.exportKey(format, key))

const exportPrivateKey = (crypto, privateKey) =>
  exportKey(crypto, KEY_FORMAT_PKCS8, privateKey)

const exportPublicKey = (crypto, publicKey) =>
  exportKey(crypto, KEY_FORMAT_SPKI, publicKey)

const exportKeyPair = async (crypto, { publicKey, privateKey }) => ({
  publicKey: await exportPublicKey(crypto, publicKey),
  privateKey: await exportPrivateKey(crypto, privateKey)
})

export default exportKeyPair
