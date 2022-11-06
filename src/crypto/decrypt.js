import { createAead } from './utils'

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
