import { createFrom } from '../chunk'
import { createAead, WebCrypto } from './utils'

const encrypt = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => {
  const { name, iv, secretKey, tagLength } = await createAead(
    crypto,
    cipher,
    key,
    nonce
  )
  const ciphertext = await crypto.subtle.encrypt(
    {
      name,
      iv,
      additionalData: createFrom(associatedData),
      tagLength
    },
    secretKey,
    createFrom(message)
  )
  return createFrom(ciphertext)
}

export default encrypt
