import { Bytes, createFrom } from '../../src'

describe('createFrom', () => {
  it('should create a new chunk from a typed array', () => {
    const view = Uint16Array.from([1, 2, 3, 4])
    expect(createFrom(view)).toEqual(
      new Bytes(view.buffer, view.byteOffset, view.byteLength)
    )
  })

  it('should create an empty chunk if the given input is null or undefined', () => {
    expect(createFrom(undefined)).toEqual(Bytes.from([]))
    expect(createFrom(null)).toEqual(Bytes.from([]))
  })

  it('should create a new chunk from an array', () => {
    const bytes = [72, 105]
    expect(createFrom(bytes)).toEqual(Bytes.from(bytes))
  })

  it('should create a new chunk from an iterable', () => {
    function* generateBytes() {
      yield 1
      yield 2
      yield 3
    }
    expect(createFrom(generateBytes())).toEqual(Bytes.from([1, 2, 3]))
  })

  it('should create a new chunk from a string', () => {
    expect(createFrom('Hello World')).toEqual(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  })

  it('should be considered a view', () => {
    const chunk = createFrom([1, 2, 3, 4])
    expect(ArrayBuffer.isView(chunk)).toBe(true)
  })

  it('should decode strings correctly', () => {
    const view = Bytes.from([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
    ])
    expect(createFrom('JBSWY3DPEBLW64TMMQ======', 'base32')).toEqual(view)
    expect(createFrom('SGVsbG8gV29ybGQ=', 'base64')).toEqual(view)
    expect(createFrom('SGVsbG8gV29ybGQ', 'base64_url_unpadded')).toEqual(view)
    expect(createFrom('48656c6c6f20576f726c64', 'hex')).toEqual(view)
    expect(
      createFrom(
        '{"type":"Buffer","data":[72,101,108,108,111,32,87,111,114,108,100]}',
        'json'
      )
    ).toEqual(view)
    expect(
      createFrom(
        `-----BEGIN MY MESSAGE-----
        SGVsbG8gV29ybGQ=
        -----END MY MESSAGE-----`,
        'pem'
      )
    ).toEqual(view)
    expect(createFrom('Hello World', 'utf8')).toEqual(view)
  })

  it('should handle invalid encodings gracefully', () => {
    expect(createFrom('Hello World', 'hubba')).toEqual(Bytes.from([]))
  })
})
