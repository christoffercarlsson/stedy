import { Chunk } from '../bytes'
import decrypt from './decrypt'
import encrypt from './encrypt'
import generateKey from './generate-key'
import { getCrypto } from './utils'

export type DecryptFunction = (
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => Promise<Chunk>

export type EncryptFunction = (
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => Promise<Chunk>

export type GenerateKeyFunction = () => Promise<Chunk>

export type CipherFunctions = {
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  generateKey: GenerateKeyFunction
}

const createCipher = (cipher: string): CipherFunctions => ({
  decrypt: async (
    key: BufferSource,
    nonce: BufferSource,
    ciphertext: BufferSource,
    associatedData?: BufferSource
  ) =>
    decrypt(await getCrypto(), cipher, key, nonce, ciphertext, associatedData),

  encrypt: async (
    key: BufferSource,
    nonce: BufferSource,
    message: BufferSource,
    associatedData?: BufferSource
  ) => encrypt(await getCrypto(), cipher, key, nonce, message, associatedData),

  generateKey: async () => generateKey(await getCrypto(), cipher)
})

export default createCipher
