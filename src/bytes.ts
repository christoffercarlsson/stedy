import _alloc from './bytes/alloc'
import Bytes from './bytes/bytes'
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

const alloc = (size: number) => Bytes.fromView(_alloc(size))

const concat = (views: BufferSource[]) => Bytes.fromView(_concat(views))

const createFrom = (
  value?: string | number | Iterable<number> | BufferSource,
  encoding?: string
) => Bytes.fromView(_createFrom(value, encoding))

const fromInteger = (value: number) => Bytes.fromView(_fromInteger(value))

const fromString = (input: string, encoding?: string) =>
  Bytes.fromView(_fromString(input, encoding))

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
  createFrom,
  fromInteger,
  fromString
}
