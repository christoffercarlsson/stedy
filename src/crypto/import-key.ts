import { createFrom } from '../bytes'
import { addKeyPrefix, ensureSupportedCurve } from './utils'

const importKey = async (
  curve: string,
  key: BufferSource,
  isSigningKey: boolean,
  isPublicKey: boolean
) =>
  addKeyPrefix(
    await ensureSupportedCurve(curve),
    createFrom(key),
    isSigningKey === true,
    isPublicKey === true
  )

export default importKey
