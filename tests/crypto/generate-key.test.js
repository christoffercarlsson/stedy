import { generateKey } from '../../src/crypto'

describe('generateKey', () => {
  const keySizes = [
    { cipher: 'AES-128-GCM', keySize: 16 },
    { cipher: 'AES-256-GCM', keySize: 32 }
  ]

  keySizes.forEach(({ cipher, keySize }) => {
    it(`should generate a symmetric key of size ${keySize} for use with ${cipher}`, async () => {
      const key = await generateKey(cipher)
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.byteLength).toEqual(keySize)
    })
  })

  it('should throw an exception when trying to generate a key for an unsupported cipher', async () => {
    await expect(generateKey('AES-CBC')).rejects.toThrow('Unsupported cipher')
  })
})
