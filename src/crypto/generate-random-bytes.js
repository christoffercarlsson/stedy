import { createFrom } from '../chunk.js'

const generateRandomBytes = ({ getRandomValues }, size) =>
  createFrom(getRandomValues(new Uint8Array(size)))

export default generateRandomBytes
