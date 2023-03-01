import alloc from './alloc'
import copy from './copy'
import { ensureView } from './utils'

const toDataView = (view: Uint8Array) =>
  new DataView(view.buffer, view.byteOffset, view.byteLength)

const readFloat32 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getFloat32(byteOffset, littleEndian)

export const readFloat32BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readFloat32(chunk, byteOffset, false)

export const readFloat32LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readFloat32(chunk, byteOffset, true)

const readFloat64 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getFloat64(byteOffset, littleEndian)

export const readFloat64BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readFloat64(chunk, byteOffset, false)

export const readFloat64LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readFloat64(chunk, byteOffset, true)

export const readInt8 = (chunk: ArrayBufferView, byteOffset = 0) =>
  toDataView(ensureView(chunk)).getInt8(byteOffset)

const readInt16 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getInt16(byteOffset, littleEndian)

export const readInt16BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt16(chunk, byteOffset, false)

export const readInt16LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt16(chunk, byteOffset, true)

const readInt32 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getInt32(byteOffset, littleEndian)

export const readInt32BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt32(chunk, byteOffset, false)

export const readInt32LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt32(chunk, byteOffset, true)

const readInt64 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getBigInt64(byteOffset, littleEndian)

export const readInt64BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt64(chunk, byteOffset, false)

export const readInt64LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readInt64(chunk, byteOffset, true)

export const readUint8 = (chunk: ArrayBufferView, byteOffset = 0) =>
  toDataView(ensureView(chunk)).getUint8(byteOffset)

const readUint16 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getUint16(byteOffset, littleEndian)

export const readUint16BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readUint16(chunk, byteOffset, false)

export const readUint16LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readUint16(chunk, byteOffset, true)

const readUint32 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean
) => toDataView(ensureView(chunk)).getUint32(byteOffset, littleEndian)

export const readUint32BE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readUint32(chunk, byteOffset, false)

export const readUint32LE = (chunk: ArrayBufferView, byteOffset = 0) =>
  readUint32(chunk, byteOffset, true)

const readUint64AsRegularNumber = (
  dataView: DataView,
  byteOffset: number,
  littleEndian: boolean
) => {
  const left = dataView.getUint32(byteOffset, littleEndian)
  const right = dataView.getUint32(byteOffset + 4, littleEndian)
  return littleEndian ? left + 2 ** 32 * right : 2 ** 32 * left + right
}

const readUint64 = (
  chunk: ArrayBufferView,
  byteOffset: number,
  littleEndian: boolean,
  asRegularNumber: boolean
) => {
  const dataView = toDataView(ensureView(chunk))
  if (asRegularNumber) {
    return readUint64AsRegularNumber(dataView, byteOffset, littleEndian)
  }
  return dataView.getBigUint64(byteOffset, littleEndian)
}

export const readUint64BE = (
  chunk: ArrayBufferView,
  byteOffset = 0,
  asRegularNumber = false
) => readUint64(chunk, byteOffset, false, asRegularNumber)

export const readUint64LE = (
  chunk: ArrayBufferView,
  byteOffset = 0,
  asRegularNumber = false
) => readUint64(chunk, byteOffset, true, asRegularNumber)

const writeFloat32 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setFloat32(byteOffset, value, littleEndian)
  return view
}

export const writeFloat32BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeFloat32(chunk, value, byteOffset, false)

export const writeFloat32LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeFloat32(chunk, value, byteOffset, true)

const writeFloat64 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setFloat64(byteOffset, value, littleEndian)
  return view
}

export const writeFloat64BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeFloat64(chunk, value, byteOffset, false)

export const writeFloat64LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeFloat64(chunk, value, byteOffset, true)

export const writeInt8 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => {
  const view = copy(chunk)
  toDataView(view).setInt8(byteOffset, value)
  return view
}

const writeInt16 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setInt16(byteOffset, value, littleEndian)
  return view
}

export const writeInt16BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeInt16(chunk, value, byteOffset, false)

export const writeInt16LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeInt16(chunk, value, byteOffset, true)

const writeInt32 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setInt32(byteOffset, value, littleEndian)
  return view
}

export const writeInt32BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeInt32(chunk, value, byteOffset, false)

export const writeInt32LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeInt32(chunk, value, byteOffset, true)

const writeInt64 = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setBigInt64(byteOffset, BigInt(value), littleEndian)
  return view
}

export const writeInt64BE = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset = 0
) => writeInt64(chunk, value, byteOffset, false)

export const writeInt64LE = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset = 0
) => writeInt64(chunk, value, byteOffset, true)

export const writeUint8 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => {
  const view = copy(chunk)
  toDataView(view).setUint8(byteOffset, value)
  return view
}

const writeUint16 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setUint16(byteOffset, value, littleEndian)
  return view
}

export const writeUint16BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeUint16(chunk, value, byteOffset, false)

export const writeUint16LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeUint16(chunk, value, byteOffset, true)

const writeUint32 = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setUint32(byteOffset, value, littleEndian)
  return view
}

export const writeUint32BE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeUint32(chunk, value, byteOffset, false)

export const writeUint32LE = (
  chunk: ArrayBufferView,
  value: number,
  byteOffset = 0
) => writeUint32(chunk, value, byteOffset, true)

const writeUint64 = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset: number,
  littleEndian: boolean
) => {
  const view = copy(chunk)
  toDataView(view).setBigUint64(byteOffset, BigInt(value), littleEndian)
  return view
}

export const writeUint64BE = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset = 0
) => writeUint64(chunk, value, byteOffset, false)

export const writeUint64LE = (
  chunk: ArrayBufferView,
  value: number | bigint,
  byteOffset = 0
) => writeUint64(chunk, value, byteOffset, true)

export const fromInteger = (value: number) => {
  const chunk = alloc(4)
  return value < 0 ? writeInt32BE(chunk, value) : writeUint32BE(chunk, value)
}
