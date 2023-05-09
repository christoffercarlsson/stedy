import { concat, createFrom } from '../bytes'
import {
  CIPHER_CHACHA20_POLY1305,
  CIPHER_CHACHA20_POLY1305_TAG_SIZE
} from './constants'
import {
  createCipherParams,
  createNodeDecipher,
  importSecretKey,
  WebCrypto
} from './utils'

const decryptChaCha20Poly1305 = async (
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => {
  const decipher = await createNodeDecipher(
    CIPHER_CHACHA20_POLY1305,
    key,
    nonce,
    associatedData
  )
  const [ciphertext, authTag] = createFrom(message).read(
    message.byteLength - CIPHER_CHACHA20_POLY1305_TAG_SIZE
  )
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  decipher.setAuthTag(authTag)
  return concat([decipher.update(ciphertext), decipher.final()])
}

const decrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => {
  if (cipher === CIPHER_CHACHA20_POLY1305) {
    return decryptChaCha20Poly1305(key, nonce, ciphertext, associatedData)
  }
  const params = await createCipherParams(cipher, nonce, associatedData)
  const message = await crypto.subtle.decrypt(
    params,
    await importSecretKey(crypto, cipher, key),
    createFrom(ciphertext)
  )
  return createFrom(message)
}

export default decrypt
