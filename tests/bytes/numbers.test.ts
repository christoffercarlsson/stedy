import { alloc } from '../../src/bytes'

describe('Numbers', () => {
  it('should store a signed 32-bit floating-point value', () => {
    const value = 1.2345
    expect(alloc(4).writeFloat32BE(value).readFloat32BE()).toBeCloseTo(value)
    expect(alloc(4).writeFloat32LE(value).readFloat32LE()).toBeCloseTo(value)
  })

  it('should store a signed 64-bit floating-point value', () => {
    const value = 5.4321
    expect(alloc(8).writeFloat64BE(value).readFloat64BE()).toBeCloseTo(value)
    expect(alloc(8).writeFloat64LE(value).readFloat64LE()).toBeCloseTo(value)
  })

  it('should store a signed 8-bit integer value', () => {
    const value = 127
    expect(alloc(1).writeInt8(value).readInt8()).toEqual(value)
  })

  it('should store an unsigned 8-bit integer value', () => {
    const value = 255
    expect(alloc(1).writeUint8(value).readUint8()).toEqual(value)
  })

  it('should store a signed 16-bit integer value', () => {
    const value = 32767
    expect(alloc(2).writeInt16BE(value).readInt16BE()).toEqual(value)
    expect(alloc(2).writeInt16LE(value).readInt16LE()).toEqual(value)
  })

  it('should store an unsigned 16-bit integer value', () => {
    const value = 65535
    expect(alloc(2).writeUint16BE(value).readUint16BE()).toEqual(value)
    expect(alloc(2).writeUint16LE(value).readUint16LE()).toEqual(value)
  })

  it('should store a signed 32-bit integer value', () => {
    const value = 2147483647
    expect(alloc(4).writeInt32BE(value).readInt32BE()).toEqual(value)
    expect(alloc(4).writeInt32LE(value).readInt32LE()).toEqual(value)
  })

  it('should store an unsigned 32-bit integer value', () => {
    const value = 4294967295
    expect(alloc(4).writeUint32BE(value).readUint32BE()).toEqual(value)
    expect(alloc(4).writeUint32LE(value).readUint32LE()).toEqual(value)
  })

  it('should store a signed 64-bit integer value', () => {
    const value = 9223372036854775807n
    expect(alloc(8).writeInt64BE(value).readInt64BE()).toEqual(value)
    expect(alloc(8).writeInt64LE(value).readInt64LE()).toEqual(value)
  })

  it('should store an unsigned 64-bit integer value', () => {
    const value = 18446744073709551615n
    expect(alloc(8).writeUint64BE(value).readUint64BE()).toEqual(value)
    expect(alloc(8).writeUint64LE(value).readUint64LE()).toEqual(value)
  })

  it('should read 64-bit integer values as regular numbers', () => {
    const offset = 0
    const value = 42n
    const a = alloc(8).writeUint64BE(value, offset)
    const b = alloc(8).writeUint64LE(value, offset)
    expect(a.readUint64BE(offset, true)).toEqual(42)
    expect(b.readUint64LE(offset, true)).toEqual(42)
  })
})
