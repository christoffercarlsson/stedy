import { createFrom } from '../chunk.js'
import { addKeyPrefix, ensureSupportedCurve } from './utils.js'

const importKey = async (curve, isSigningKey, isPublicKey, key) =>
  addKeyPrefix(
    await ensureSupportedCurve(curve),
    isSigningKey === true,
    isPublicKey === true,
    createFrom(key)
  )

export default importKey
