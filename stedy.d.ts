declare const ENCODING_BASE32 = 'base32'
declare const ENCODING_BASE64 = 'base64'
declare const ENCODING_BASE64_URLSAFE = 'base64url'
declare const ENCODING_HEX = 'hex'
declare const ENCODING_JSON = 'json'
declare const ENCODING_PEM = 'pem'
declare const ENCODING_UTF8 = 'utf8'

declare class Bytes extends Uint8Array {
  static fromView(view: ArrayBufferView): Bytes

  static from(
    arrayLike: Iterable<number> | ArrayLike<number>,
    mapFn?: (v: number, k: number) => number
  ): Bytes

  get size(): number

  append(view: BufferSource): Bytes

  copy(): Bytes

  decode(encoding?: string): Bytes

  encode(encoding?: string, label?: string): Bytes

  endsWith(view: BufferSource): boolean

  equals(view: BufferSource): boolean

  getBytes(): number[]

  hasSize(size: number): boolean

  isEmpty(): boolean

  padLeft(size: number): Bytes

  padRight(size: number): Bytes

  prepend(view: BufferSource): Bytes

  read(...sizes: number[]): Bytes[]

  readFloat32BE(byteOffset?: number): number

  readFloat32LE(byteOffset?: number): number

  readFloat64BE(byteOffset?: number): number

  readFloat64LE(byteOffset?: number): number

  readInt8(byteOffset?: number): number

  readInt16BE(byteOffset?: number): number

  readInt16LE(byteOffset?: number): number

  readInt32BE(byteOffset?: number): number

  readInt32LE(byteOffset?: number): number

  readInt64BE(byteOffset?: number): bigint

  readInt64LE(byteOffset?: number): bigint

  readUint8(byteOffset?: number): number

  readUint16BE(byteOffset?: number): number

  readUint16LE(byteOffset?: number): number

  readUint32BE(byteOffset?: number): number

  readUint32LE(byteOffset?: number): number

  readUint64BE(byteOffset?: number, asRegularNumber?: boolean): number | bigint

  readUint64LE(byteOffset?: number, asRegularNumber?: boolean): number | bigint

  slice(start?: number, end?: number): Bytes

  split(size: number, appendRemainder?: boolean): Bytes[]

  startsWith(view: BufferSource): boolean

  subarray(begin?: number, end?: number): Bytes

  toJSON(): {
    type: string
    data: number[]
  }

  toString(encoding?: string, label?: string): string

  transcode(currentEncoding: string, targetEncoding: string): Bytes

  trimLeft(byte?: number): Bytes

  trimRight(byte?: number): Bytes

  writeFloat32BE(value: number, byteOffset?: number): Bytes

  writeFloat32LE(value: number, byteOffset?: number): Bytes

  writeFloat64BE(value: number, byteOffset?: number): Bytes

  writeFloat64LE(value: number, byteOffset?: number): Bytes

  writeInt8(value: number, byteOffset?: number): Bytes

  writeInt16BE(value: number, byteOffset?: number): Bytes

  writeInt16LE(value: number, byteOffset?: number): Bytes

  writeInt32BE(value: number, byteOffset?: number): Bytes

  writeInt32LE(value: number, byteOffset?: number): Bytes

  writeInt64BE(value: number | bigint, byteOffset?: number): Bytes

  writeInt64LE(value: number | bigint, byteOffset?: number): Bytes

  writeUint8(value: number, byteOffset?: number): Bytes

  writeUint16BE(value: number, byteOffset?: number): Bytes

  writeUint16LE(value: number, byteOffset?: number): Bytes

  writeUint32BE(value: number, byteOffset?: number): Bytes

  writeUint32LE(value: number, byteOffset?: number): Bytes

  writeUint64BE(value: number | bigint, byteOffset?: number): Bytes

  writeUint64LE(value: number | bigint, byteOffset?: number): Bytes

  xor(view: BufferSource): Bytes
}

type DecryptFunction = (
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => Promise<Bytes>

type EncryptFunction = (
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => Promise<Bytes>

type GenerateKeyFunction = () => Promise<Bytes>

type GenerateNonceFunction = () => Promise<Bytes>

type CipherFunctions = {
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  generateKey: GenerateKeyFunction
  generateNonce: GenerateNonceFunction
}

declare const createCipher: (cipher: string) => CipherFunctions

declare const decrypt: DecryptFunction,
  encrypt: EncryptFunction,
  generateKey: GenerateKeyFunction,
  generateNonce: GenerateNonceFunction

declare const generateRandomBytes: (size: number) => Promise<Bytes>

type DiffieHellmanFunction = (
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource,
  size?: number
) => Promise<Bytes>

type GenerateKeyPairFunction = () => Promise<{
  publicKey: Bytes
  privateKey: Bytes
}>

type ImportKeyFunction = (
  key: BufferSource,
  isSigningKey: boolean,
  isPublicKey: boolean
) => Promise<Bytes>

type SignFunction = (
  privateKey: BufferSource,
  message: BufferSource
) => Promise<Bytes>

type VerifyFunction = (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => Promise<boolean>

type CurveFunctions = {
  diffieHellman: DiffieHellmanFunction
  generateKeyPair: GenerateKeyPairFunction
  generateSignKeyPair: GenerateKeyPairFunction
  importKey: ImportKeyFunction
  sign: SignFunction
  verify: VerifyFunction
}

declare const createCurve: (curve: string, hash?: string) => CurveFunctions

type HashFunction = (
  message: BufferSource,
  iterations?: number
) => Promise<Bytes>

type HKDFFunction = (
  message: BufferSource,
  salt: BufferSource,
  info?: BufferSource,
  size?: number
) => Promise<Bytes>

type HMACFunction = (key: BufferSource, message: BufferSource) => Promise<Bytes>

type PBKDF2Function = (
  password: BufferSource,
  salt: BufferSource,
  iterations?: number,
  size?: number
) => Promise<Bytes>

type HashFunctions = {
  hash: HashFunction
  hkdf: HKDFFunction
  hmac: HMACFunction
  pbkdf2: PBKDF2Function
}

declare const createHash: (algorithm: string) => HashFunctions

declare const diffieHellman: DiffieHellmanFunction,
  generateKeyPair: GenerateKeyPairFunction,
  generateSignKeyPair: GenerateKeyPairFunction,
  importKey: ImportKeyFunction,
  sign: SignFunction,
  verify: VerifyFunction

declare const hash: HashFunction,
  hkdf: HKDFFunction,
  hmac: HMACFunction,
  pbkdf2: PBKDF2Function

export type {
  CipherFunctions,
  CurveFunctions,
  DecryptFunction,
  DiffieHellmanFunction,
  EncryptFunction,
  GenerateKeyFunction,
  GenerateKeyPairFunction,
  GenerateNonceFunction,
  HashFunctions,
  HashFunction,
  HKDFFunction,
  HMACFunction,
  ImportKeyFunction,
  PBKDF2Function,
  SignFunction,
  VerifyFunction
}

declare const alloc: (size: number) => Uint8Array

declare const concat: (views: BufferSource[]) => Uint8Array

declare const createFrom: (
  value?: string | number | Iterable<number> | BufferSource,
  encoding?: string
) => Uint8Array

declare const exportKey: (key: BufferSource) => Promise<Bytes>

declare const fromInteger: (value: number) => Uint8Array

declare const fromString: (input: string, encoding?: string) => Bytes

declare const getCiphers: () => string[]

declare const getCurves: () => string[]

declare const getHashes: () => string[]

export {
  ENCODING_BASE32,
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8,
  alloc,
  concat,
  Bytes,
  createCipher,
  createCurve,
  createFrom,
  createHash,
  decrypt,
  diffieHellman,
  encrypt,
  exportKey,
  fromInteger,
  fromString,
  generateKey,
  generateKeyPair,
  generateNonce,
  generateRandomBytes,
  generateSignKeyPair,
  getCiphers,
  getCurves,
  getHashes,
  hash,
  hkdf,
  hmac,
  importKey,
  pbkdf2,
  sign,
  verify
}
