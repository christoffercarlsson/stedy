import { createAead } from './utils.js'

const decrypt = (
  crypto,
  name,
  key,
  iv,
  tagLength,
  ciphertext,
  additionalData
) =>
  crypto.subtle.decrypt(
    {
      name,
      iv,
      additionalData,
      tagLength
    },
    key,
    ciphertext
  )

export default createAead(decrypt)
