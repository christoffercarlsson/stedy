import { randomBytes } from '../../src'

describe('randomBytes', () => {
  it('should generate a set of psuedo-random bytes of a given size', async () => {
    const size = 16
    const chunk = await randomBytes(size)
    expect(chunk).toBeInstanceOf(Uint8Array)
    expect(chunk.byteLength).toEqual(size)
  })
})
