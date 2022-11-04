import { describe, it, expect } from '../../src/test.js'
import { Chunk, createFrom } from '../../src/chunk.js'

export default describe('Chunk', () => [
  it('should allocate a new zero-filled chunk with a given size', () => {
    expect(Chunk.alloc(4)).toEqual(Chunk.from([0, 0, 0, 0]))
  }),

  it('should create a new chunk by concatenating all the chunks in a given list together', () => {
    const views = [
      Chunk.from([72, 101, 108, 108]),
      Chunk.from([111, 32, 87]),
      createFrom([111, 114, 108])
    ]
    expect(Chunk.concat(views)).toEqual(
      Chunk.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  }),

  it('should create a copy of a given chunk', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const chunk = Chunk.from(bytes)
    expect(Chunk.copy(chunk)).toEqual(chunk)
    expect(Chunk.copy(chunk)).not.toBe(chunk)
  }),

  it('should have an alias "size" for the byteLength property', () => {
    const chunk = Chunk.from('Hello')
    expect(chunk.size).toEqual(chunk.byteLength)
  }),

  it('should append the data from another chunk', () => {
    const a = Chunk.from('Hel')
    const b = createFrom('lo')
    expect(a.append(b)).toEqual(Chunk.from('Hello'))
  }),

  it('should check to see if a chunk ends with a given chunk', () => {
    const chunk = Chunk.from('Hello World')
    expect(chunk.endsWith(createFrom(' World'))).toBe(true)
    expect(chunk.endsWith(Chunk.from(' World'))).toBe(true)
    expect(chunk.endsWith(createFrom('Hello'))).toBe(false)
    expect(chunk.endsWith(Chunk.from('Hello'))).toBe(false)
  }),

  it('should check to see if the chunk is equal to another chunk', () => {
    const greeting = 'Hello World'
    const chunk = Chunk.from(greeting)
    expect(chunk.equals(createFrom(greeting))).toBe(true)
    expect(chunk.equals(Chunk.from(greeting))).toBe(true)
    expect(chunk.equals(createFrom('Hello'))).toBe(false)
    expect(chunk.equals(Chunk.from('Hello'))).toBe(false)
  }),

  it('should get the bytes from a given chunk', () => {
    expect(Chunk.from('Hello World').getBytes()).toEqual([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
    ])
  }),

  it('should check to see if the chunk is of a given size', () => {
    const chunk = Chunk.from('Hello')
    expect(chunk.hasSize(5)).toBe(true)
    expect(chunk.hasSize(6)).toBe(false)
  }),

  it('should check to see if the chunk is empty', () => {
    expect(Chunk.from('Hello').isEmpty()).toBe(false)
    expect(Chunk.from().isEmpty()).toBe(true)
  }),

  it('should prepend the data from anohter chunk', () => {
    const a = Chunk.from('lo')
    const b = createFrom('Hel')
    expect(a.prepend(b)).toEqual(Chunk.from('Hello'))
  }),

  it('should read data sequentially', () => {
    const [a, b] = Chunk.from('Hello World').read(5)
    expect(a).toEqual(Chunk.from('Hello'))
    expect(b).toEqual(Chunk.from(' World'))
  }),

  it('should split a chunk into smaller chunks', () => {
    const chunk = Chunk.from('Hello')
    expect(chunk.split(2)).toEqual([
      Chunk.from('He'),
      Chunk.from('ll'),
      Chunk.from('o')
    ])
    expect(chunk.split(2, true)).toEqual([Chunk.from('He'), Chunk.from('llo')])
  }),

  it('should check to see if a chunk starts with a given chunk', () => {
    const chunk = Chunk.from('Hello World')
    expect(chunk.startsWith(createFrom('Hello'))).toBe(true)
    expect(chunk.startsWith(Chunk.from('Hello'))).toBe(true)
    expect(chunk.startsWith(createFrom('World'))).toBe(false)
    expect(chunk.startsWith(Chunk.from('World'))).toBe(false)
  }),

  it('should create a new chunk from a string based on a given encoding', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.from(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(Chunk.decode(buffer.toString(encoding), encoding)).toEqual(chunk)
    })
    expect(Chunk.decode(JSON.stringify(buffer), 'json')).toEqual(chunk)
    expect(
      Chunk.decode(
        `-----BEGIN GREETING-----
        ${buffer.toString('base64')}
        -----END GREETING-----`,
        'pem'
      )
    ).toEqual(chunk)
  }),

  it('should encode chunks correctly', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.from(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(chunk.encode(encoding).toString()).toEqual(
        buffer.toString(encoding)
      )
    })
    expect(chunk.encode('json').toString()).toEqual(JSON.stringify(buffer))
    expect(chunk.encode('pem', 'greeting').toString()).toEqual(
      `-----BEGIN GREETING-----
${buffer.toString('base64')}
-----END GREETING-----`
    )
  }),

  it('should convert a chunk to a string based on a given encoding', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.from(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(chunk.toString(encoding)).toEqual(buffer.toString(encoding))
    })
    expect(chunk.toString('json')).toEqual(JSON.stringify(buffer))
    expect(chunk.toString('pem', 'GREETING')).toEqual(
      `-----BEGIN GREETING-----
${buffer.toString('base64')}
-----END GREETING-----`
    )
  }),

  it('should stringify a chunk into a correct JSON representation', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.from(bytes)
    expect(JSON.stringify(chunk)).toEqual(JSON.stringify(buffer))
  }),

  it('should store a signed 32-bit floating-point value', () => {
    const value = 1.2345
    expect(Chunk.alloc(4).writeFloat32BE(value).readFloat32BE()).toBeCloseTo(
      value
    )
    expect(Chunk.alloc(4).writeFloat32LE(value).readFloat32LE()).toBeCloseTo(
      value
    )
  }),

  it('should store a signed 64-bit floating-point value', () => {
    const value = 5.4321
    expect(Chunk.alloc(8).writeFloat64BE(value).readFloat64BE()).toBeCloseTo(
      value
    )
    expect(Chunk.alloc(8).writeFloat64LE(value).readFloat64LE()).toBeCloseTo(
      value
    )
  }),

  it('should store a signed 8-bit integer value', () => {
    const value = 127
    expect(Chunk.alloc(1).writeInt8(value).readInt8()).toEqual(value)
  }),

  it('should store an unsigned 8-bit integer value', () => {
    const value = 255
    expect(Chunk.alloc(1).writeUint8(value).readUint8()).toEqual(value)
  }),

  it('should store a signed 16-bit integer value', () => {
    const value = 32767
    expect(Chunk.alloc(2).writeInt16BE(value).readInt16BE()).toEqual(value)
    expect(Chunk.alloc(2).writeInt16LE(value).readInt16LE()).toEqual(value)
  }),

  it('should store an unsigned 16-bit integer value', () => {
    const value = 65535
    expect(Chunk.alloc(2).writeUint16BE(value).readUint16BE()).toEqual(value)
    expect(Chunk.alloc(2).writeUint16LE(value).readUint16LE()).toEqual(value)
  }),

  it('should store a signed 32-bit integer value', () => {
    const value = 2147483647
    expect(Chunk.alloc(4).writeInt32BE(value).readInt32BE()).toEqual(value)
    expect(Chunk.alloc(4).writeInt32LE(value).readInt32LE()).toEqual(value)
  }),

  it('should store an unsigned 32-bit integer value', () => {
    const value = 4294967295
    expect(Chunk.alloc(4).writeUint32BE(value).readUint32BE()).toEqual(value)
    expect(Chunk.alloc(4).writeUint32LE(value).readUint32LE()).toEqual(value)
  }),

  it('should store a signed 64-bit integer value', () => {
    const value = 9223372036854775807n
    expect(Chunk.alloc(8).writeInt64BE(value).readInt64BE()).toEqual(value)
    expect(Chunk.alloc(8).writeInt64LE(value).readInt64LE()).toEqual(value)
  }),

  it('should store an unsigned 64-bit integer value', () => {
    const value = 18446744073709551615n
    expect(Chunk.alloc(8).writeUint64BE(value).readUint64BE()).toEqual(value)
    expect(Chunk.alloc(8).writeUint64LE(value).readUint64LE()).toEqual(value)
  }),

  it('should pad a given chunk with zeroes on the left', () => {
    expect(Chunk.from([1, 2, 3]).padLeft(6)).toEqual(
      Chunk.from([0, 0, 0, 1, 2, 3])
    )
  }),

  it('should pad a given chunk with zeroes on the right', () => {
    expect(Chunk.from([1, 2, 3]).padRight(6)).toEqual(
      Chunk.from([1, 2, 3, 0, 0, 0])
    )
  }),

  it('should trim leading zeroes', () => {
    expect(Chunk.from([0, 0, 0, 1, 2, 3]).trimLeft()).toEqual(
      Chunk.from([1, 2, 3])
    )
  }),

  it('should trim trailing zeroes', () => {
    expect(Chunk.from([1, 2, 3, 0, 0, 0]).trimRight()).toEqual(
      Chunk.from([1, 2, 3])
    )
  }),

  it('should calculate the XOR of two given chunks', () => {
    const a = Chunk.from([
      43, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216
    ])
    const b = Chunk.from([
      253, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195
    ])
    const result = Chunk.from([
      214, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27
    ])
    expect(a.xor(b)).toEqual(result)
  })
])
