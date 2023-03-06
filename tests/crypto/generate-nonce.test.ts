import { createCipher } from '../../src'

describe('generateNonce', () => {
  const keySizes = [
    { cipher: 'AES-128-CBC', nonceSize: 16 },
    { cipher: 'AES-128-CTR', nonceSize: 16 },
    { cipher: 'AES-128-GCM', nonceSize: 12 },
    { cipher: 'AES-256-CBC', nonceSize: 16 },
    { cipher: 'AES-256-CTR', nonceSize: 16 },
    { cipher: 'AES-256-GCM', nonceSize: 12 }
  ]

  keySizes.forEach(({ cipher, nonceSize }) => {
    it(`should generate a nonce of size ${nonceSize} bytes for use with ${cipher}`, async () => {
      const { generateNonce } = createCipher(cipher)
      const nonce = await generateNonce()
      expect(nonce).toBeInstanceOf(Uint8Array)
      expect(nonce.byteLength).toEqual(nonceSize)
    })
  })

  it('should throw an exception when trying to generate a nonce for an unsupported cipher', async () => {
    const { generateNonce } = createCipher('hubba')
    await expect(generateNonce()).rejects.toThrow('Invalid nonce size')
  })
})
