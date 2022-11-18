import _alloc from './bytes/alloc'
import Chunk from './bytes/chunk'
import _concat from './bytes/concat'
import {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './bytes/constants'
import _createFrom from './bytes/create-from'
import { fromString as _fromString } from './bytes/decode'

const alloc = (size: number) => Chunk.fromView(_alloc(size))

const concat = (views: ArrayBufferView[]) => Chunk.fromView(_concat(views))

const createFrom = (
  value?: string | Iterable<number> | BufferSource,
  encoding?: string
) => Chunk.fromView(_createFrom(value, encoding))

const fromString = (input: string, encoding?: string) =>
  Chunk.fromView(_fromString(input, encoding))

export {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8,
  alloc,
  concat,
  Chunk,
  createFrom,
  fromString
}
