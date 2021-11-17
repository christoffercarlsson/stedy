import { createFrom } from '../chunk.js'
import { ALGORITHM_HKDF } from './constants.js'
import { ensureSupportedHash, getHashSize, importHkdfKey } from './utils.js'

const hkdf = async (crypto, hash, key, salt, info, size) =>
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
