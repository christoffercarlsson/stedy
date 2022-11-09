import { createFrom } from '../../chunk'
import { KEY_FORMAT_PKCS8, KEY_FORMAT_SPKI } from '../constants'
import { WebCrypto } from '../utils'

const exportKey = async (
  crypto: WebCrypto,
  format: 'pkcs8' | 'spki',
  key: CryptoKey
) => createFrom(await crypto.subtle.exportKey(format, key))

const exportPrivateKey = (crypto: WebCrypto, privateKey: CryptoKey) =>
  exportKey(crypto, KEY_FORMAT_PKCS8, privateKey)

const exportPublicKey = (crypto: WebCrypto, publicKey: CryptoKey) =>
  exportKey(crypto, KEY_FORMAT_SPKI, publicKey)

const exportKeyPair = async (
  crypto: WebCrypto,
  { publicKey, privateKey }: CryptoKeyPair
) => ({
  publicKey: await exportPublicKey(crypto, publicKey),
  privateKey: await exportPrivateKey(crypto, privateKey)
})

export default exportKeyPair
