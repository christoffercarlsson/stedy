import { createFrom } from '../bytes'
import { ALGORITHM_PBKDF2, PBKDF2_DEFAULT_ITERATIONS } from './constants'
import {
  ensureSupportedHash,
  getHashSize,
  importPbkdf2Key,
  WebCrypto
} from './utils'

const pbkdf2 = async (
  crypto: WebCrypto,
  hash: string,
  password: BufferSource,
  salt: BufferSource,
  iterations?: number,
  size?: number
) =>
  createFrom(
    await crypto.subtle.deriveBits(
      {
        name: ALGORITHM_PBKDF2,
        hash: await ensureSupportedHash(hash),
        salt: createFrom(salt),
        iterations:
          Number.isInteger(iterations) && iterations > 0
            ? iterations
            : PBKDF2_DEFAULT_ITERATIONS
      },
      await importPbkdf2Key(crypto, createFrom(password)),
      (Number.isInteger(size) && size > 0 ? size : getHashSize(hash)) * 8
    )
  )

export default pbkdf2
