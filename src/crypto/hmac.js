import { createFrom } from '../chunk'
import { ALGORITHM_HMAC } from './constants'
import { ensureSupportedHash, importHmacKey } from './utils'

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
