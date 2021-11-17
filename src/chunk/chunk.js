import alloc from './alloc.js'
import append from './append.js'
import concat from './concat.js'
import copy from './copy.js'
import createFrom from './create-from.js'
import decode from './decode.js'
import encode, { toString } from './encode.js'
import endsWith from './ends-with.js'
import equals from './equals.js'
import getBytes from './get-bytes.js'
import hasSize from './has-size.js'
import isEmpty from './is-empty.js'
import { padLeft, padRight } from './pad.js'
import {
  readFloat32BE,
  readFloat32LE,
  readFloat64BE,
  readFloat64LE,
  readInt8,
  readInt16BE,
  readInt16LE,
  readInt32BE,
  readInt32LE,
  readInt64BE,
  readInt64LE,
  readUint8,
  readUint16BE,
  readUint16LE,
  readUint32BE,
  readUint32LE,
  readUint64BE,
  readUint64LE,
  writeFloat32BE,
  writeFloat32LE,
  writeFloat64BE,
  writeFloat64LE,
  writeInt8,
  writeInt16BE,
  writeInt16LE,
  writeInt32BE,
  writeInt32LE,
  writeInt64BE,
  writeInt64LE,
  writeUint8,
  writeUint16BE,
  writeUint16LE,
  writeUint32BE,
  writeUint32LE,
  writeUint64BE,
  writeUint64LE
} from './numbers.js'
import prepend from './prepend.js'
import read from './read.js'
import split from './split.js'
import startsWith from './starts-with.js'
import { trimLeft, trimRight } from './trim.js'
import { createJSONObject } from './utils.js'
import xor from './xor.js'

class Chunk extends Uint8Array {
  static alloc(size) {
    return this.from(alloc(size))
  }

  static concat(views) {
    return this.from(concat(views))
  }

  static copy(view) {
    return this.from(copy(view))
  }

  static decode(value, encoding) {
    return this.from(decode(value, encoding))
  }

  static from(value, encoding) {
    const view = createFrom(value, encoding)
    return Reflect.construct(this, [
      view.buffer,
      view.byteOffset,
      view.byteLength
    ])
  }

  get size() {
    return this.byteLength
  }

  append(view) {
    return this.constructor.from(append(this, view))
  }

  encode(encoding, label) {
    return this.constructor.from(encode(this, encoding, label))
  }

  endsWith(view) {
    return endsWith(this, view)
  }

  equals(view) {
    return equals(this, view)
  }

  getBytes() {
    return getBytes(this)
  }

  hasSize(size) {
    return hasSize(this, size)
  }

  isEmpty() {
    return isEmpty(this)
  }

  padLeft(size) {
    return this.constructor.from(padLeft(this, size))
  }

  padRight(size) {
    return this.constructor.from(padRight(this, size))
  }

  prepend(view) {
    return this.constructor.from(prepend(this, view))
  }

  read(...sizes) {
    return read(this, ...sizes).map((view) => this.constructor.from(view))
  }

  readFloat32BE(byteOffset) {
    return readFloat32BE(this, byteOffset)
  }

  readFloat32LE(byteOffset) {
    return readFloat32LE(this, byteOffset)
  }

  readFloat64BE(byteOffset) {
    return readFloat64BE(this, byteOffset)
  }

  readFloat64LE(byteOffset) {
    return readFloat64LE(this, byteOffset)
  }

  readInt8(byteOffset) {
    return readInt8(this, byteOffset)
  }

  readInt16BE(byteOffset) {
    return readInt16BE(this, byteOffset)
  }

  readInt16LE(byteOffset) {
    return readInt16LE(this, byteOffset)
  }

  readInt32BE(byteOffset) {
    return readInt32BE(this, byteOffset)
  }

  readInt32LE(byteOffset) {
    return readInt32LE(this, byteOffset)
  }

  readInt64BE(byteOffset) {
    return readInt64BE(this, byteOffset)
  }

  readInt64LE(byteOffset) {
    return readInt64LE(this, byteOffset)
  }

  readUint8(byteOffset) {
    return readUint8(this, byteOffset)
  }

  readUint16BE(byteOffset) {
    return readUint16BE(this, byteOffset)
  }

  readUint16LE(byteOffset) {
    return readUint16LE(this, byteOffset)
  }

  readUint32BE(byteOffset) {
    return readUint32BE(this, byteOffset)
  }

  readUint32LE(byteOffset) {
    return readUint32LE(this, byteOffset)
  }

  readUint64BE(byteOffset) {
    return readUint64BE(this, byteOffset)
  }

  readUint64LE(byteOffset) {
    return readUint64LE(this, byteOffset)
  }

  split(size, appendRemainder) {
    return split(this, size, appendRemainder).map((view) =>
      this.constructor.from(view)
    )
  }

  startsWith(view) {
    return startsWith(this, view)
  }

  toJSON() {
    return createJSONObject(this)
  }

  toString(encoding, label) {
    return toString(this, encoding, label)
  }

  trimLeft(byte) {
    return this.constructor.from(trimLeft(this, byte))
  }

  trimRight(byte) {
    return this.constructor.from(trimRight(this, byte))
  }

  writeFloat32BE(value, byteOffset) {
    return this.constructor.from(writeFloat32BE(this, value, byteOffset))
  }

  writeFloat32LE(value, byteOffset) {
    return this.constructor.from(writeFloat32LE(this, value, byteOffset))
  }

  writeFloat64BE(value, byteOffset) {
    return this.constructor.from(writeFloat64BE(this, value, byteOffset))
  }

  writeFloat64LE(value, byteOffset) {
    return this.constructor.from(writeFloat64LE(this, value, byteOffset))
  }

  writeInt8(value, byteOffset) {
    return this.constructor.from(writeInt8(this, value, byteOffset))
  }

  writeInt16BE(value, byteOffset) {
    return this.constructor.from(writeInt16BE(this, value, byteOffset))
  }

  writeInt16LE(value, byteOffset) {
    return this.constructor.from(writeInt16LE(this, value, byteOffset))
  }

  writeInt32BE(value, byteOffset) {
    return this.constructor.from(writeInt32BE(this, value, byteOffset))
  }

  writeInt32LE(value, byteOffset) {
    return this.constructor.from(writeInt32LE(this, value, byteOffset))
  }

  writeInt64BE(value, byteOffset) {
    return this.constructor.from(writeInt64BE(this, value, byteOffset))
  }

  writeInt64LE(value, byteOffset) {
    return this.constructor.from(writeInt64LE(this, value, byteOffset))
  }

  writeUint8(value, byteOffset) {
    return this.constructor.from(writeUint8(this, value, byteOffset))
  }

  writeUint16BE(value, byteOffset) {
    return this.constructor.from(writeUint16BE(this, value, byteOffset))
  }

  writeUint16LE(value, byteOffset) {
    return this.constructor.from(writeUint16LE(this, value, byteOffset))
  }

  writeUint32BE(value, byteOffset) {
    return this.constructor.from(writeUint32BE(this, value, byteOffset))
  }

  writeUint32LE(value, byteOffset) {
    return this.constructor.from(writeUint32LE(this, value, byteOffset))
  }

  writeUint64BE(value, byteOffset) {
    return this.constructor.from(writeUint64BE(this, value, byteOffset))
  }

  writeUint64LE(value, byteOffset) {
    return this.constructor.from(writeUint64LE(this, value, byteOffset))
  }

  xor(view) {
    return this.constructor.from(xor(this, view))
  }
}

export default Chunk
