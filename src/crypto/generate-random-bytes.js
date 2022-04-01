import { createFrom } from '../chunk.js'

const generateRandomBytes = (crypto, size) =>
  createFrom(crypto.getRandomValues(new Uint8Array(size)))

export default generateRandomBytes
