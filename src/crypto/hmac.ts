import { createFrom } from '../chunk'
import { ALGORITHM_HMAC } from './constants'
import { ensureSupportedHash, importHmacKey, WebCrypto } from './utils'

const hmac = async (
  crypto: WebCrypto,
  algorithm: string,
  key: BufferSource,
  message: BufferSource
) =>
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
