import { createFrom } from '../chunk.js'
import { ALGORITHM_HMAC } from './constants.js'
import { ensureSupportedHash, importHmacKey } from './utils.js'

const hmac = async (crypto, algorithm, key, message) =>
  createFrom(
    await crypto.subtle.sign(
      ALGORITHM_HMAC,
      await importHmacKey(
        crypto,
        await ensureSupportedHash(algorithm),
        createFrom(key)
      ),
      createFrom(message)
    )
  )

export default hmac
