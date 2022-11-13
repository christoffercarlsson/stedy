import { createFrom } from '../bytes'
import { createCipherParams, importSecretKey, WebCrypto } from './utils'

const decrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => {
  const params = await createCipherParams(cipher, nonce, associatedData)
  const message = await crypto.subtle.decrypt(
    params,
    await importSecretKey(crypto, cipher, key),
    createFrom(ciphertext)
  )
  return createFrom(message)
}

export default decrypt
