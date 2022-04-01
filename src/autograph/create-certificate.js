import { concat, createFrom, ENCODING_BASE64_URLSAFE } from '../chunk.js'

const ensureArray = (value) => {
  if (
    value !== undefined &&
    value !== null &&
    typeof value[Symbol.iterator] === 'function'
  ) {
    return [...value]
  }
  return []
}

const createCertificate = (entries, encoding = ENCODING_BASE64_URLSAFE) =>
  ensureArray(entries).reduce(
    (certificate, [identityKey, signature]) =>
      concat([
        certificate,
        createFrom(identityKey, encoding),
        createFrom(signature, encoding)
      ]),
    createFrom()
  )

export default createCertificate
