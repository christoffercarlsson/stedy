import { createFrom } from '../chunk'
import generateRandomBytes from './generate-random-bytes'
import { ensureSupportedCipher, getKeySize } from './utils'

const generateKey = async (crypto, cipher) =>
  createFrom(
    generateRandomBytes(crypto, getKeySize(await ensureSupportedCipher(cipher)))
  )

export default generateKey
