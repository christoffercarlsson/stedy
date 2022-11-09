import { createFrom } from '../chunk'
import { ALGORITHM_HKDF } from './constants'
import {
  ensureSupportedHash,
  getHashSize,
  importHkdfKey,
  WebCrypto
} from './utils'

const hkdf = async (
  crypto: WebCrypto,
  hash: string,
  key: BufferSource,
  salt: BufferSource,
  info?: BufferSource,
  size?: number
) =>
  createFrom(
    await crypto.subtle.deriveBits(
      {
        name: ALGORITHM_HKDF,
        hash: await ensureSupportedHash(hash),
        salt: createFrom(salt),
        info: createFrom(info)
      },
      await importHkdfKey(crypto, createFrom(key)),
      (Number.isInteger(size) && size > 0 ? size : getHashSize(hash)) * 8
    )
  )

export default hkdf
