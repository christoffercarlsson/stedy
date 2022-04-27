import { concat, createFrom, read } from '../chunk.js'
import { authenticate } from './authenticate.js'
import { KEY_CONTEXT_RESPONDER, PUBLIC_KEY_SIZE } from './constants.js'
import { ensureValidPublicKey, signData } from './utils.js'

const sign = async (
  signingFunction,
  ourCertificate,
  secretKey,
  ourKeyShare,
  theirKeyShare,
  theirData
) => {
  const [theirIdentityPublicKey] = read(theirKeyShare, PUBLIC_KEY_SIZE)
  const data = concat([
    createFrom(theirData),
    await ensureValidPublicKey(theirIdentityPublicKey)
  ])
  const signature = await signData(signingFunction, data)
  return authenticate(
    signingFunction,
    signature,
    ourCertificate,
    secretKey,
    ourKeyShare,
    theirKeyShare,
    KEY_CONTEXT_RESPONDER
  )
}

export default sign
