import { createFrom } from '../bytes'
import generateRandomBytes from './generate-random-bytes'
import { ensureSupportedCipher, getKeySize, WebCrypto } from './utils'

const generateKey = async (crypto: WebCrypto, cipher: string) =>
  createFrom(
    generateRandomBytes(crypto, getKeySize(await ensureSupportedCipher(cipher)))
  )

export default generateKey
