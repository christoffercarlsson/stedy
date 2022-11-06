import { createFrom } from '../chunk'
import { ensureSupportedKey, removeKeyPrefix } from './utils'

const exportKey = async (key) => {
  const prefixedKey = createFrom(key)
  await ensureSupportedKey(prefixedKey)
  return removeKeyPrefix(prefixedKey)
}

export default exportKey
