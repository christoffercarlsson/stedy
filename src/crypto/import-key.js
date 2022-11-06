import { createFrom } from '../chunk'
import { addKeyPrefix, ensureSupportedCurve } from './utils'

const importKey = async (curve, isSigningKey, isPublicKey, key) =>
  addKeyPrefix(
    await ensureSupportedCurve(curve),
    isSigningKey === true,
    isPublicKey === true,
    createFrom(key)
  )

export default importKey
