import { createFrom } from '../chunk'

const generateRandomBytes = (crypto, size) =>
  createFrom(crypto.getRandomValues(new Uint8Array(size)))

export default generateRandomBytes
