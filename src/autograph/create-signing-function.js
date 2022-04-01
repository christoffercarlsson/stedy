import { createFrom, ENCODING_BASE64_URLSAFE } from '../chunk.js'
import { sign as createSignature } from '../crypto.js'
import { importPrivateSigningKey } from './utils.js'

const createSigningFunction = (
  ourPrivateKey,
  encoding = ENCODING_BASE64_URLSAFE
) => {
  const privateKey = createFrom(ourPrivateKey, encoding)
  return async (data) => {
    const signature = await createSignature(
      createFrom(data),
      await importPrivateSigningKey(privateKey)
    )
    return signature
  }
}

export default createSigningFunction
