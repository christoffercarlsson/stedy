import { createFrom } from '../chunk.js'
import generateRandomBytes from './generate-random-bytes.js'
import { ensureSupportedCipher, getKeySize } from './utils.js'

const generateKey = async (crypto, cipher) =>
  createFrom(
    generateRandomBytes(crypto, getKeySize(await ensureSupportedCipher(cipher)))
  )

export default generateKey
