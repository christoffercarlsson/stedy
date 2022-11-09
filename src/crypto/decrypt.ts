import { createFrom } from '../chunk'
import { createAead, WebCrypto } from './utils'

const decrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => {
  const { name, iv, secretKey, tagLength } = await createAead(
    crypto,
    cipher,
    key,
    nonce
  )
  const message = await crypto.subtle.decrypt(
    {
      name,
      iv,
      additionalData: createFrom(associatedData),
      tagLength
    },
    secretKey,
    createFrom(ciphertext)
  )
  return createFrom(message)
}

export default decrypt
