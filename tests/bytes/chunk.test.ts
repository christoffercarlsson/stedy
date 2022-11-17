/* eslint-disable @typescript-eslint/no-loss-of-precision */
/* eslint-disable no-loss-of-precision */
import { Chunk, createFrom } from '../../src/bytes'

describe('Chunk', () => {
  it('should allocate a new zero-filled chunk with a given size', () => {
    expect(Chunk.alloc(4)).toEqual(Chunk.createFrom([0, 0, 0, 0]))
  })

  it('should create a new chunk by concatenating all the chunks in a given list together', () => {
    const views = [
      Chunk.createFrom([72, 101, 108, 108]),
      Chunk.createFrom([111, 32, 87]),
      createFrom([111, 114, 108])
    ]
    expect(Chunk.concat(views)).toEqual(
      Chunk.createFrom([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  })

  it('should create a copy of a given chunk', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const chunk = Chunk.createFrom(bytes)
    expect(Chunk.copy(chunk)).toEqual(chunk)
    expect(Chunk.copy(chunk)).not.toBe(chunk)
  })

  it('should have an alias "size" for the byteLength property', () => {
    const chunk = Chunk.createFrom('Hello')
    expect(chunk.size).toEqual(chunk.byteLength)
  })

  it('should append the data from another chunk', () => {
    const a = Chunk.createFrom('Hel')
    const b = createFrom('lo')
    expect(a.append(b)).toEqual(Chunk.createFrom('Hello'))
  })

  it('should check to see if a chunk ends with a given chunk', () => {
    const chunk = Chunk.createFrom('Hello World')
    expect(chunk.endsWith(createFrom(' World'))).toBe(true)
    expect(chunk.endsWith(Chunk.createFrom(' World'))).toBe(true)
    expect(chunk.endsWith(createFrom('Hello'))).toBe(false)
    expect(chunk.endsWith(Chunk.createFrom('Hello'))).toBe(false)
  })

  it('should check to see if the chunk is equal to another chunk', () => {
    const greeting = 'Hello World'
    const chunk = Chunk.createFrom(greeting)
    expect(chunk.equals(createFrom(greeting))).toBe(true)
    expect(chunk.equals(Chunk.createFrom(greeting))).toBe(true)
    expect(chunk.equals(createFrom('Hello'))).toBe(false)
    expect(chunk.equals(Chunk.createFrom('Hello'))).toBe(false)
  })

  it('should get the bytes from a given chunk', () => {
    expect(Chunk.createFrom('Hello World').getBytes()).toEqual([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
    ])
  })

  it('should check to see if the chunk is of a given size', () => {
    const chunk = Chunk.createFrom('Hello')
    expect(chunk.hasSize(5)).toBe(true)
    expect(chunk.hasSize(6)).toBe(false)
  })

  it('should check to see if the chunk is empty', () => {
    expect(Chunk.createFrom('Hello').isEmpty()).toBe(false)
    expect(Chunk.createFrom([]).isEmpty()).toBe(true)
  })

  it('should prepend the data from anohter chunk', () => {
    const a = Chunk.createFrom('lo')
    const b = createFrom('Hel')
    expect(a.prepend(b)).toEqual(Chunk.createFrom('Hello'))
  })

  it('should read data sequentially', () => {
    const [a, b] = Chunk.createFrom('Hello World').read(5)
    expect(a).toEqual(Chunk.createFrom('Hello'))
    expect(b).toEqual(Chunk.createFrom(' World'))
  })

  it('should split a chunk into smaller chunks', () => {
    const chunk = Chunk.createFrom('Hello')
    expect(chunk.split(2)).toEqual([
      Chunk.createFrom('He'),
      Chunk.createFrom('ll'),
      Chunk.createFrom('o')
    ])
    expect(chunk.split(2, true)).toEqual([
      Chunk.createFrom('He'),
      Chunk.createFrom('llo')
    ])
  })

  it('should check to see if a chunk starts with a given chunk', () => {
    const chunk = Chunk.createFrom('Hello World')
    expect(chunk.startsWith(createFrom('Hello'))).toBe(true)
    expect(chunk.startsWith(Chunk.createFrom('Hello'))).toBe(true)
    expect(chunk.startsWith(createFrom('World'))).toBe(false)
    expect(chunk.startsWith(Chunk.createFrom('World'))).toBe(false)
  })

  it('should create a new chunk from a string based on a given encoding', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.createFrom(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(
        // eslint-disable-next-line no-undef
        Chunk.decode(buffer.toString(encoding as BufferEncoding), encoding)
      ).toEqual(chunk)
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
  })

  it('should encode chunks correctly', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.createFrom(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(chunk.encode(encoding).toString()).toEqual(
        // eslint-disable-next-line no-undef
        buffer.toString(encoding as BufferEncoding)
      )
    })
    expect(chunk.encode('json').toString()).toEqual(JSON.stringify(buffer))
    expect(chunk.encode('pem', 'greeting').toString()).toEqual(
      `-----BEGIN GREETING-----
${buffer.toString('base64')}
-----END GREETING-----`
    )
  })

  it('should convert a chunk to a string based on a given encoding', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.createFrom(bytes)
    ;['base64', 'hex', 'utf8'].forEach((encoding) => {
      expect(chunk.toString(encoding)).toEqual(
        // eslint-disable-next-line no-undef
        buffer.toString(encoding as BufferEncoding)
      )
    })
    expect(chunk.toString('json')).toEqual(JSON.stringify(buffer))
    expect(chunk.toString('pem', 'GREETING')).toEqual(
      `-----BEGIN GREETING-----
${buffer.toString('base64')}
-----END GREETING-----`
    )
  })

  it('should stringify a chunk into a correct JSON representation', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = Chunk.createFrom(bytes)
    expect(JSON.stringify(chunk)).toEqual(JSON.stringify(buffer))
  })

  it('should store a signed 32-bit floating-point value', () => {
    const value = 1.2345
    expect(Chunk.alloc(4).writeFloat32BE(value).readFloat32BE()).toBeCloseTo(
      value
    )
    expect(Chunk.alloc(4).writeFloat32LE(value).readFloat32LE()).toBeCloseTo(
      value
    )
  })

  it('should store a signed 64-bit floating-point value', () => {
    const value = 5.4321
    expect(Chunk.alloc(8).writeFloat64BE(value).readFloat64BE()).toBeCloseTo(
      value
    )
    expect(Chunk.alloc(8).writeFloat64LE(value).readFloat64LE()).toBeCloseTo(
      value
    )
  })

  it('should store a signed 8-bit integer value', () => {
    const value = 127
    expect(Chunk.alloc(1).writeInt8(value).readInt8()).toEqual(value)
  })

  it('should store an unsigned 8-bit integer value', () => {
    const value = 255
    expect(Chunk.alloc(1).writeUint8(value).readUint8()).toEqual(value)
  })

  it('should store a signed 16-bit integer value', () => {
    const value = 32767
    expect(Chunk.alloc(2).writeInt16BE(value).readInt16BE()).toEqual(value)
    expect(Chunk.alloc(2).writeInt16LE(value).readInt16LE()).toEqual(value)
  })

  it('should store an unsigned 16-bit integer value', () => {
    const value = 65535
    expect(Chunk.alloc(2).writeUint16BE(value).readUint16BE()).toEqual(value)
    expect(Chunk.alloc(2).writeUint16LE(value).readUint16LE()).toEqual(value)
  })

  it('should store a signed 32-bit integer value', () => {
    const value = 2147483647
    expect(Chunk.alloc(4).writeInt32BE(value).readInt32BE()).toEqual(value)
    expect(Chunk.alloc(4).writeInt32LE(value).readInt32LE()).toEqual(value)
  })

  it('should store an unsigned 32-bit integer value', () => {
    const value = 4294967295
    expect(Chunk.alloc(4).writeUint32BE(value).readUint32BE()).toEqual(value)
    expect(Chunk.alloc(4).writeUint32LE(value).readUint32LE()).toEqual(value)
  })

  it('should store a signed 64-bit integer value', () => {
    const value = 9223372036854775807n
    expect(Chunk.alloc(8).writeInt64BE(value).readInt64BE()).toEqual(value)
    expect(Chunk.alloc(8).writeInt64LE(value).readInt64LE()).toEqual(value)
  })

  it('should store an unsigned 64-bit integer value', () => {
    const value = 18446744073709551615n
    expect(Chunk.alloc(8).writeUint64BE(value).readUint64BE()).toEqual(value)
    expect(Chunk.alloc(8).writeUint64LE(value).readUint64LE()).toEqual(value)
  })

  it('should pad a given chunk with zeroes on the left', () => {
    expect(Chunk.createFrom([1, 2, 3]).padLeft(6)).toEqual(
      Chunk.createFrom([0, 0, 0, 1, 2, 3])
    )
  })

  it('should pad a given chunk with zeroes on the right', () => {
    expect(Chunk.createFrom([1, 2, 3]).padRight(6)).toEqual(
      Chunk.createFrom([1, 2, 3, 0, 0, 0])
    )
  })

  it('should re-encode a given chunk from one encoding to another', () => {
    expect(
      Chunk.createFrom([
        52, 56, 54, 53, 54, 99, 54, 99, 54, 102, 50, 48, 53, 55, 54, 102, 55,
        50, 54, 99, 54, 52
      ]).transcode('hex', 'base64url')
    ).toEqual(
      Chunk.createFrom([
        83, 71, 86, 115, 98, 71, 56, 103, 86, 50, 57, 121, 98, 71, 81
      ])
    )
  })

  it('should trim leading zeroes', () => {
    expect(Chunk.createFrom([0, 0, 0, 1, 2, 3]).trimLeft()).toEqual(
      Chunk.createFrom([1, 2, 3])
    )
  })

  it('should trim trailing zeroes', () => {
    expect(Chunk.createFrom([1, 2, 3, 0, 0, 0]).trimRight()).toEqual(
      Chunk.createFrom([1, 2, 3])
    )
  })

  it('should calculate the XOR of two given chunks', () => {
    const a = Chunk.createFrom([
      43, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216
    ])
    const b = Chunk.createFrom([
      253, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195
    ])
    const result = Chunk.createFrom([
      214, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27
    ])
    expect(a.xor(b)).toEqual(result)
  })

  it('should be considered a view', () => {
    const chunk = Chunk.createFrom([1, 2, 3, 4])
    expect(ArrayBuffer.isView(chunk)).toBe(true)
  })
})
