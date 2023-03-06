import _alloc from './bytes/alloc'
import Chunk from './bytes/chunk'
import _concat from './bytes/concat'
import {
  ENCODING_BASE32,
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './bytes/constants'
import _createFrom from './bytes/create-from'
import { fromString as _fromString } from './bytes/decode'
import { fromInteger as _fromInteger } from './bytes/numbers'

const alloc = (size: number) => Chunk.fromView(_alloc(size))

const concat = (views: BufferSource[]) => Chunk.fromView(_concat(views))

const createFrom = (
  value?: string | number | Iterable<number> | BufferSource,
  encoding?: string
) => Chunk.fromView(_createFrom(value, encoding))

const fromInteger = (value: number) => Chunk.fromView(_fromInteger(value))

const fromString = (input: string, encoding?: string) =>
  Chunk.fromView(_fromString(input, encoding))

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
  Chunk,
  createFrom,
  fromInteger,
  fromString
}
