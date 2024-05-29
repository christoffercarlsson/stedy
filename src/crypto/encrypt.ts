import { createFrom } from '../bytes'
import { createCipherParams, importSecretKey, WebCrypto } from './utils'

const encrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => {
  const params = await createCipherParams(cipher, nonce, associatedData)
  const ciphertext = await crypto.subtle.encrypt(
    params,
    await importSecretKey(crypto, cipher, key),
    createFrom(message)
  )
  return createFrom(ciphertext)
}

export default encrypt
