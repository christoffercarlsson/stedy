import { generateRandomBytes } from '../../src/crypto'

describe('generateRandomBytes', () => {
  it('should generate a set of psuedo-random bytes of a given size', async () => {
    const size = 16
    const chunk = await generateRandomBytes(size)
    expect(chunk).toBeInstanceOf(Uint8Array)
    expect(chunk.byteLength).toEqual(size)
  })
})
