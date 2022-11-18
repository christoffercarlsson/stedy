import { createFrom } from '../bytes'
import randomBytes from './random-bytes'
import { ensureSupportedCipher, getKeySize, WebCrypto } from './utils'

const generateKey = async (crypto: WebCrypto, cipher: string) =>
  createFrom(
    randomBytes(crypto, getKeySize(await ensureSupportedCipher(cipher)))
  )

export default generateKey
