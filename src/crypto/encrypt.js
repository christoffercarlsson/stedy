import { createAead } from './utils.js'

const encrypt = (crypto, name, key, iv, tagLength, message, additionalData) =>
  crypto.subtle.encrypt(
    {
      name,
      iv,
      additionalData,
      tagLength
    },
    key,
    message
  )

export default createAead(encrypt)
