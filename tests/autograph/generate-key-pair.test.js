import { describe, expect, it } from '../../src/test.js'
import { generateKeyPair } from '../../src/autograph.js'

export default describe('generateKeyPair', () =>
  it('should generate an Ed25519 identity key pair', async () => {
    const { publicKey, privateKey } = await generateKeyPair()
    expect(publicKey.byteLength).toBe(32)
    expect(privateKey.byteLength).toBe(32)
  }))
