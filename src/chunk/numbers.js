import copy from './copy.js'
import { ensureView } from './utils.js'

const toDataView = (view) =>
  new DataView(view.buffer, view.byteOffset, view.byteLength)

const readFloat32 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getFloat32(byteOffset, littleEndian)

export const readFloat32BE = (chunk, byteOffset = 0) =>
  readFloat32(chunk, byteOffset, false)

export const readFloat32LE = (chunk, byteOffset = 0) =>
  readFloat32(chunk, byteOffset, true)

const readFloat64 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getFloat64(byteOffset, littleEndian)

export const readFloat64BE = (chunk, byteOffset = 0) =>
  readFloat64(chunk, byteOffset, false)

export const readFloat64LE = (chunk, byteOffset = 0) =>
  readFloat64(chunk, byteOffset, true)

export const readInt8 = (chunk, byteOffset = 0) =>
  toDataView(ensureView(chunk)).getInt8(byteOffset)

const readInt16 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getInt16(byteOffset, littleEndian)

export const readInt16BE = (chunk, byteOffset = 0) =>
  readInt16(chunk, byteOffset, false)

export const readInt16LE = (chunk, byteOffset = 0) =>
  readInt16(chunk, byteOffset, true)

const readInt32 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getInt32(byteOffset, littleEndian)

export const readInt32BE = (chunk, byteOffset = 0) =>
  readInt32(chunk, byteOffset, false)

export const readInt32LE = (chunk, byteOffset = 0) =>
  readInt32(chunk, byteOffset, true)

const readInt64 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getBigInt64(byteOffset, littleEndian)

export const readInt64BE = (chunk, byteOffset = 0) =>
  readInt64(chunk, byteOffset, false)

export const readInt64LE = (chunk, byteOffset = 0) =>
  readInt64(chunk, byteOffset, true)

export const readUint8 = (chunk, byteOffset = 0) =>
  toDataView(ensureView(chunk)).getUint8(byteOffset)

const readUint16 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getUint16(byteOffset, littleEndian)

export const readUint16BE = (chunk, byteOffset = 0) =>
  readUint16(chunk, byteOffset, false)

export const readUint16LE = (chunk, byteOffset = 0) =>
  readUint16(chunk, byteOffset, true)

const readUint32 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getUint32(byteOffset, littleEndian)

export const readUint32BE = (chunk, byteOffset = 0) =>
  readUint32(chunk, byteOffset, false)

export const readUint32LE = (chunk, byteOffset = 0) =>
  readUint32(chunk, byteOffset, true)

const readUint64 = (chunk, byteOffset, littleEndian) =>
  toDataView(ensureView(chunk)).getBigUint64(byteOffset, littleEndian)

export const readUint64BE = (chunk, byteOffset = 0) =>
  readUint64(chunk, byteOffset, false)

export const readUint64LE = (chunk, byteOffset = 0) =>
  readUint64(chunk, byteOffset, true)

const writeFloat32 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setFloat32(byteOffset, value, littleEndian)
  return view
}

export const writeFloat32BE = (chunk, value, byteOffset = 0) =>
  writeFloat32(chunk, value, byteOffset, false)

export const writeFloat32LE = (chunk, value, byteOffset = 0) =>
  writeFloat32(chunk, value, byteOffset, true)

const writeFloat64 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setFloat64(byteOffset, value, littleEndian)
  return view
}

export const writeFloat64BE = (chunk, value, byteOffset = 0) =>
  writeFloat64(chunk, value, byteOffset, false)

export const writeFloat64LE = (chunk, value, byteOffset = 0) =>
  writeFloat64(chunk, value, byteOffset, true)

export const writeInt8 = (chunk, value, byteOffset = 0) => {
  const view = copy(chunk)
  toDataView(view).setInt8(byteOffset, value)
  return view
}

const writeInt16 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setInt16(byteOffset, value, littleEndian)
  return view
}

export const writeInt16BE = (chunk, value, byteOffset = 0) =>
  writeInt16(chunk, value, byteOffset, false)

export const writeInt16LE = (chunk, value, byteOffset = 0) =>
  writeInt16(chunk, value, byteOffset, true)

const writeInt32 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setInt32(byteOffset, value, littleEndian)
  return view
}

export const writeInt32BE = (chunk, value, byteOffset = 0) =>
  writeInt32(chunk, value, byteOffset, false)

export const writeInt32LE = (chunk, value, byteOffset = 0) =>
  writeInt32(chunk, value, byteOffset, true)

const writeInt64 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setBigInt64(byteOffset, BigInt(value), littleEndian)
  return view
}

export const writeInt64BE = (chunk, value, byteOffset = 0) =>
  writeInt64(chunk, value, byteOffset, false)

export const writeInt64LE = (chunk, value, byteOffset = 0) =>
  writeInt64(chunk, value, byteOffset, true)

export const writeUint8 = (chunk, value, byteOffset = 0) => {
  const view = copy(chunk)
  toDataView(view).setUint8(byteOffset, value)
  return view
}

const writeUint16 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setUint16(byteOffset, value, littleEndian)
  return view
}

export const writeUint16BE = (chunk, value, byteOffset = 0) =>
  writeUint16(chunk, value, byteOffset, false)

export const writeUint16LE = (chunk, value, byteOffset = 0) =>
  writeUint16(chunk, value, byteOffset, true)

const writeUint32 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setUint32(byteOffset, value, littleEndian)
  return view
}

export const writeUint32BE = (chunk, value, byteOffset = 0) =>
  writeUint32(chunk, value, byteOffset, false)

export const writeUint32LE = (chunk, value, byteOffset = 0) =>
  writeUint32(chunk, value, byteOffset, true)

const writeUint64 = (chunk, value, byteOffset, littleEndian) => {
  const view = copy(chunk)
  toDataView(view).setBigUint64(byteOffset, BigInt(value), littleEndian)
  return view
}

export const writeUint64BE = (chunk, value, byteOffset = 0) =>
  writeUint64(chunk, value, byteOffset, false)

export const writeUint64LE = (chunk, value, byteOffset = 0) =>
  writeUint64(chunk, value, byteOffset, true)
