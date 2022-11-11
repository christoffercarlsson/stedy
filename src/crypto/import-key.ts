import { createFrom } from '../bytes'
import { addKeyPrefix, ensureSupportedCurve } from './utils'

const importKey = async (
  curve: string,
  isSigningKey: boolean,
  isPublicKey: boolean,
  key: BufferSource
) =>
  addKeyPrefix(
    await ensureSupportedCurve(curve),
    isSigningKey === true,
    isPublicKey === true,
    createFrom(key)
  )

export default importKey
