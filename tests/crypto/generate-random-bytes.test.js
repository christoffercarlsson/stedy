import { describe, it, expect } from '../../dist/test.js'
import { generateRandomBytes } from '../../dist/crypto.js'

export default describe('generateRandomBytes', () =>
  it('should generate a set of psuedo-random bytes of a given size', async () => {
    const size = 16
    const chunk = await generateRandomBytes(size)
    expect(chunk).toBeInstanceOf(Uint8Array)
    expect(chunk.byteLength).toEqual(size)
  }))
