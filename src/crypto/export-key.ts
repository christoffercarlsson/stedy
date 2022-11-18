import { createFrom } from '../bytes'
import { ensureSupportedKey, removeKeyPrefix } from './utils'

const exportKey = async (key: BufferSource) =>
  createFrom(removeKeyPrefix(await ensureSupportedKey(key)))

export default exportKey
