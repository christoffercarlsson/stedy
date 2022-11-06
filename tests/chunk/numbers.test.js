import {
  alloc,
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
} from '../../src/chunk'

describe('Numbers', () => {
  it('should store a signed 32-bit floating-point value at the specified byte offset', () => {
    const offset = 0
    const value = 1.2345
    const a = writeFloat32BE(alloc(4), value, offset)
    const b = writeFloat32LE(alloc(4), value, offset)
    expect(readFloat32BE(a, offset)).toBeCloseTo(value)
    expect(readFloat32LE(b, offset)).toBeCloseTo(value)
  })

  it('should store a signed 64-bit floating-point value at the specified byte offset', () => {
    const offset = 0
    const value = 5.4321
    const a = writeFloat64BE(alloc(8), value, offset)
    const b = writeFloat64LE(alloc(8), value, offset)
    expect(readFloat64BE(a, offset)).toBeCloseTo(value)
    expect(readFloat64LE(b, offset)).toBeCloseTo(value)
  })

  it('should store a signed 8-bit integer value at the specified byte offset', () => {
    const offset = 2
    const value = 127
    const view = writeInt8(alloc(4), value, offset)
    expect(readInt8(view, offset)).toEqual(value)
  })

  it('should store an unsigned 8-bit integer value at the specified byte offset', () => {
    const offset = 0
    const value = 255
    const view = writeUint8(alloc(4), value, offset)
    expect(readUint8(view, offset)).toEqual(value)
  })

  it('should store a signed 16-bit integer value at the specified byte offset', () => {
    const offset = 2
    const value = 32767
    const a = writeInt16BE(alloc(4), value, offset)
    const b = writeInt16LE(alloc(4), value, offset)
    expect(readInt16BE(a, offset)).toEqual(value)
    expect(readInt16LE(b, offset)).toEqual(value)
  })

  it('should store an unsigned 16-bit integer value at the specified byte offset', () => {
    const offset = 2
    const value = 65535
    const a = writeUint16BE(alloc(4), value, offset)
    const b = writeUint16LE(alloc(4), value, offset)
    expect(readUint16BE(a, offset)).toEqual(value)
    expect(readUint16LE(b, offset)).toEqual(value)
  })

  it('should store a signed 32-bit integer value at the specified byte offset', () => {
    const offset = 0
    const value = 2147483647
    const a = writeInt32BE(alloc(4), value, offset)
    const b = writeInt32LE(alloc(4), value, offset)
    expect(readInt32BE(a, offset)).toEqual(value)
    expect(readInt32LE(b, offset)).toEqual(value)
  })

  it('should store an unsigned 32-bit integer value at the specified byte offset', () => {
    const offset = 0
    const value = 4294967295
    const a = writeUint32BE(alloc(4), value, offset)
    const b = writeUint32LE(alloc(4), value, offset)
    expect(readUint32BE(a, offset)).toEqual(value)
    expect(readUint32LE(b, offset)).toEqual(value)
  })

  it('should store a signed 64-bit integer value at the specified byte offset', () => {
    const offset = 0
    const value = 9223372036854775807n
    const a = writeInt64BE(alloc(8), value, offset)
    const b = writeInt64LE(alloc(8), value, offset)
    expect(readInt64BE(a, offset)).toEqual(value)
    expect(readInt64LE(b, offset)).toEqual(value)
  })

  it('should store an unsigned 64-bit integer value at the specified byte offset', () => {
    const offset = 0
    const value = 18446744073709551615n
    const a = writeUint64BE(alloc(8), value, offset)
    const b = writeUint64LE(alloc(8), value, offset)
    expect(readUint64BE(a, offset)).toEqual(value)
    expect(readUint64LE(b, offset)).toEqual(value)
  })

  it('should handle signed 64-bit integer values gracefully', () => {
    const offset = 0
    const value = 42
    const a = writeInt64BE(alloc(8), value, offset)
    const b = writeInt64LE(alloc(8), value, offset)
    expect(readInt64BE(a, offset)).toEqual(BigInt(value)) // eslint-disable-line no-undef
    expect(readInt64LE(b, offset)).toEqual(BigInt(value)) // eslint-disable-line no-undef
  })

  it('should handle unsigned 64-bit integer values gracefully', () => {
    const offset = 0
    const value = 42
    const a = writeUint64BE(alloc(8), value, offset)
    const b = writeUint64LE(alloc(8), value, offset)
    expect(readUint64BE(a, offset)).toEqual(BigInt(value)) // eslint-disable-line no-undef
    expect(readUint64LE(b, offset)).toEqual(BigInt(value)) // eslint-disable-line no-undef
  })
})
