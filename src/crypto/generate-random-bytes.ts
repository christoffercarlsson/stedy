import { alloc, createFrom } from '../bytes'
import { WebCrypto } from './utils'

const generateRandomBytes = (crypto: WebCrypto, size: number) =>
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  createFrom(crypto.getRandomValues(alloc(size)) as Uint8Array)

export default generateRandomBytes
