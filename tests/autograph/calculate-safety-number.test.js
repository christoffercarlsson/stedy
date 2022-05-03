import { describe, it, expect } from '../../dist/test.js'
import { generateKeyPair, calculateSafetyNumber } from '../../dist/autograph.js'

export default describe('calculateSafetyNumber', () =>
  it('should calculate a safety number given the public keys of both parties', async () => {
    const { publicKey: alice } = await generateKeyPair()
    const { publicKey: bob } = await generateKeyPair()
    const a = await calculateSafetyNumber(alice, bob)
    const b = await calculateSafetyNumber(bob, alice)
    expect(a.byteLength).toBe(60)
    expect(a).toEqual(b)
  }))
