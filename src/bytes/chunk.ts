import alloc from './alloc'
import append from './append'
import concat from './concat'
import copy from './copy'
import createFrom from './create-from'
import decode from './decode'
import encode, { toString } from './encode'
import endsWith from './ends-with'
import equals from './equals'
import getBytes from './get-bytes'
import hasSize from './has-size'
import isEmpty from './is-empty'
import { padLeft, padRight } from './pad'
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
} from './numbers'
import prepend from './prepend'
import read from './read'
import split from './split'
import startsWith from './starts-with'
import { trimLeft, trimRight } from './trim'
import { createJSONObject } from './utils'
import xor from './xor'
import transcode from './transcode'

class Chunk extends Uint8Array {
  static alloc(size: number) {
    return this.createFrom(alloc(size))
  }

  static concat(views: ArrayBufferView[]) {
    return this.createFrom(concat(views))
  }

  static copy(view: ArrayBufferView) {
    return this.createFrom(copy(view))
  }

  static decode(value: string | ArrayBufferView, encoding?: string) {
    return this.createFrom(decode(value, encoding))
  }

  static createFrom(
    value?: string | Iterable<number> | BufferSource,
    encoding?: string
  ) {
    const view = createFrom(value, encoding)
    return Reflect.construct(this, [
      view.buffer,
      view.byteOffset,
      view.byteLength
    ]) as Chunk
  }

  get size() {
    return this.byteLength
  }

  append(view: ArrayBufferView) {
    return (this.constructor as typeof Chunk).createFrom(append(this, view))
  }

  encode(encoding?: string, label?: string) {
    return (this.constructor as typeof Chunk).createFrom(
      encode(this, encoding, label)
    )
  }

  endsWith(view: ArrayBufferView) {
    return endsWith(this, view)
  }

  equals(view: ArrayBufferView) {
    return equals(this, view)
  }

  getBytes() {
    return getBytes(this)
  }

  hasSize(size: number) {
    return hasSize(this, size)
  }

  isEmpty() {
    return isEmpty(this)
  }

  padLeft(size: number) {
    return (this.constructor as typeof Chunk).createFrom(padLeft(this, size))
  }

  padRight(size: number) {
    return (this.constructor as typeof Chunk).createFrom(padRight(this, size))
  }

  prepend(view: ArrayBufferView) {
    return (this.constructor as typeof Chunk).createFrom(prepend(this, view))
  }

  read(...sizes: number[]) {
    return read(this, ...sizes).map((view: ArrayBufferView) =>
      (this.constructor as typeof Chunk).createFrom(view)
    )
  }

  readFloat32BE(byteOffset?: number) {
    return readFloat32BE(this, byteOffset)
  }

  readFloat32LE(byteOffset?: number) {
    return readFloat32LE(this, byteOffset)
  }

  readFloat64BE(byteOffset?: number) {
    return readFloat64BE(this, byteOffset)
  }

  readFloat64LE(byteOffset?: number) {
    return readFloat64LE(this, byteOffset)
  }

  readInt8(byteOffset?: number) {
    return readInt8(this, byteOffset)
  }

  readInt16BE(byteOffset?: number) {
    return readInt16BE(this, byteOffset)
  }

  readInt16LE(byteOffset?: number) {
    return readInt16LE(this, byteOffset)
  }

  readInt32BE(byteOffset?: number) {
    return readInt32BE(this, byteOffset)
  }

  readInt32LE(byteOffset?: number) {
    return readInt32LE(this, byteOffset)
  }

  readInt64BE(byteOffset?: number) {
    return readInt64BE(this, byteOffset)
  }

  readInt64LE(byteOffset?: number) {
    return readInt64LE(this, byteOffset)
  }

  readUint8(byteOffset?: number) {
    return readUint8(this, byteOffset)
  }

  readUint16BE(byteOffset?: number) {
    return readUint16BE(this, byteOffset)
  }

  readUint16LE(byteOffset?: number) {
    return readUint16LE(this, byteOffset)
  }

  readUint32BE(byteOffset?: number) {
    return readUint32BE(this, byteOffset)
  }

  readUint32LE(byteOffset?: number) {
    return readUint32LE(this, byteOffset)
  }

  readUint64BE(byteOffset?: number, asRegularNumber?: boolean) {
    return readUint64BE(this, byteOffset, asRegularNumber)
  }

  readUint64LE(byteOffset?: number, asRegularNumber?: boolean) {
    return readUint64LE(this, byteOffset, asRegularNumber)
  }

  split(size: number, appendRemainder?: boolean) {
    return split(this, size, appendRemainder).map((view) =>
      (this.constructor as typeof Chunk).createFrom(view)
    )
  }

  startsWith(view: ArrayBufferView) {
    return startsWith(this, view)
  }

  toJSON() {
    return createJSONObject(this)
  }

  toString(encoding?: string, label?: string) {
    return toString(this, encoding, label)
  }

  transcode(currentEncoding: string, targetEncoding: string) {
    return (this.constructor as typeof Chunk).createFrom(
      transcode(this, currentEncoding, targetEncoding)
    )
  }

  trimLeft(byte?: number) {
    return (this.constructor as typeof Chunk).createFrom(trimLeft(this, byte))
  }

  trimRight(byte?: number) {
    return (this.constructor as typeof Chunk).createFrom(trimRight(this, byte))
  }

  writeFloat32BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeFloat32BE(this, value, byteOffset)
    )
  }

  writeFloat32LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeFloat32LE(this, value, byteOffset)
    )
  }

  writeFloat64BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeFloat64BE(this, value, byteOffset)
    )
  }

  writeFloat64LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeFloat64LE(this, value, byteOffset)
    )
  }

  writeInt8(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt8(this, value, byteOffset)
    )
  }

  writeInt16BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt16BE(this, value, byteOffset)
    )
  }

  writeInt16LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt16LE(this, value, byteOffset)
    )
  }

  writeInt32BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt32BE(this, value, byteOffset)
    )
  }

  writeInt32LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt32LE(this, value, byteOffset)
    )
  }

  writeInt64BE(value: number | bigint, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt64BE(this, value, byteOffset)
    )
  }

  writeInt64LE(value: number | bigint, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeInt64LE(this, value, byteOffset)
    )
  }

  writeUint8(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint8(this, value, byteOffset)
    )
  }

  writeUint16BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint16BE(this, value, byteOffset)
    )
  }

  writeUint16LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint16LE(this, value, byteOffset)
    )
  }

  writeUint32BE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint32BE(this, value, byteOffset)
    )
  }

  writeUint32LE(value: number, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint32LE(this, value, byteOffset)
    )
  }

  writeUint64BE(value: number | bigint, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint64BE(this, value, byteOffset)
    )
  }

  writeUint64LE(value: number | bigint, byteOffset?: number) {
    return (this.constructor as typeof Chunk).createFrom(
      writeUint64LE(this, value, byteOffset)
    )
  }

  xor(view: ArrayBufferView) {
    return (this.constructor as typeof Chunk).createFrom(xor(this, view))
  }
}

export default Chunk
