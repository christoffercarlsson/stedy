import { ensureSupportedKey, removeKeyPrefix } from './utils'

const exportKey = async (key: BufferSource) =>
  removeKeyPrefix(await ensureSupportedKey(key))

export default exportKey
