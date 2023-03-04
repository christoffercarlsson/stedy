import { Chunk } from '../bytes'
import decrypt from './decrypt'
import encrypt from './encrypt'
import generateKey from './generate-key'
import generateRandomBytes from './generate-random-bytes'
import { getCrypto } from './utils'
import { ensureValidNonce, getNonceSize } from './utils/cipher'

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

export type GenerateNonceFunction = () => Promise<Chunk>

export type CipherFunctions = {
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  generateKey: GenerateKeyFunction
  generateNonce: GenerateNonceFunction
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

  generateKey: async () => generateKey(await getCrypto(), cipher),

  generateNonce: async () =>
    ensureValidNonce(
      cipher,
      generateRandomBytes(await getCrypto(), getNonceSize(cipher))
    )
})

export default createCipher
