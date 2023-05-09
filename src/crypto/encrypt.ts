import type { Buffer } from 'buffer'
import { concat, createFrom } from '../bytes'
import { CIPHER_CHACHA20_POLY1305 } from './constants'
import {
  createCipherParams,
  createNodeCipher,
  importSecretKey,
  WebCrypto
} from './utils'

const encryptChaCha20Poly1305 = async (
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => {
  const cipher = await createNodeCipher(
    CIPHER_CHACHA20_POLY1305,
    key,
    nonce,
    associatedData
  )
  return concat(
    [
      cipher.update(createFrom(message)),
      cipher.final(),
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      cipher.getAuthTag()
    ].map((value: Buffer) => createFrom(value))
  )
}

const encrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => {
  if (cipher === CIPHER_CHACHA20_POLY1305) {
    return encryptChaCha20Poly1305(key, nonce, message, associatedData)
  }
  const params = await createCipherParams(cipher, nonce, associatedData)
  const ciphertext = await crypto.subtle.encrypt(
    params,
    await importSecretKey(crypto, cipher, key),
    createFrom(message)
  )
  return createFrom(ciphertext)
}

export default encrypt
