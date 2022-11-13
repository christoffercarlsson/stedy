import { createCipher } from '../../src/crypto'

describe('generateKey', () => {
  const keySizes = [
    { cipher: 'AES-128-CBC', keySize: 16 },
    { cipher: 'AES-128-GCM', keySize: 16 },
    { cipher: 'AES-256-CBC', keySize: 32 },
    { cipher: 'AES-256-GCM', keySize: 32 }
  ]

  keySizes.forEach(({ cipher, keySize }) => {
    it(`should generate a symmetric key of size ${keySize} bytes for use with ${cipher}`, async () => {
      const { generateKey } = createCipher(cipher)
      const key = await generateKey()
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.byteLength).toEqual(keySize)
    })
  })

  it('should throw an exception when trying to generate a key for an unsupported cipher', async () => {
    const { generateKey } = createCipher('hubba')
    await expect(generateKey()).rejects.toThrow('Unsupported cipher')
  })
})
