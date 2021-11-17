import { createFrom } from '../chunk.js'
import { ensureSupportedKey, removeKeyPrefix } from './utils.js'

const exportKey = async (key) => {
  const prefixedKey = createFrom(key)
  await ensureSupportedKey(prefixedKey)
  return removeKeyPrefix(prefixedKey)
}

export default exportKey
