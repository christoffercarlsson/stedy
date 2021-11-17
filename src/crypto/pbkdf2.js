import { createFrom } from '../chunk.js'
import { ALGORITHM_PBKDF2, PBKDF2_DEFAULT_ITERATIONS } from './constants.js'
import { ensureSupportedHash, getHashSize, importPbkdf2Key } from './utils.js'

const pbkdf2 = async (crypto, hash, password, salt, iterations, size) =>
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
