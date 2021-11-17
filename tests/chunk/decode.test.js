import { describe, it, expect } from '../../src/test.js'
import { decode } from '../../src/chunk.js'

export default describe('decode', () => [
  it('should decode Base 64 encoded chunks correctly', () => {
    expect(
      decode(
        Uint8Array.from([
          72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 43, 108,
          119, 112, 107, 47, 86, 65, 61, 61
        ]),
        'base64'
      )
    ).toEqual(
      Uint8Array.from([
        29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
      ])
    )
  }),

  it('should decode URL safe Base 64 encoded chunks correctly', () => {
    expect(
      decode(
        Uint8Array.from([
          72, 86, 110, 56, 85, 67, 109, 69, 81, 54, 70, 82, 117, 53, 45, 108,
          119, 112, 107, 95, 86, 65
        ]),
        'base64url'
      )
    ).toEqual(
      Uint8Array.from([
        29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
      ])
    )
  }),

  it('should decode hexadecimal chunks correctly', () => {
    expect(
      decode(
        Uint8Array.from([
          52, 56, 54, 53, 54, 99, 54, 99, 54, 102, 50, 48, 53, 55, 54, 102, 55,
          50, 54, 99, 54, 52
        ]),
        'hex'
      )
    ).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  }),

  it('should decode JSON correctly', () => {
    expect(
      decode(
        Uint8Array.from([
          123, 34, 116, 121, 112, 101, 34, 58, 34, 66, 117, 102, 102, 101, 114,
          34, 44, 34, 100, 97, 116, 97, 34, 58, 91, 55, 50, 44, 49, 48, 49, 44,
          49, 48, 56, 44, 49, 48, 56, 44, 49, 49, 49, 44, 51, 50, 44, 56, 55,
          44, 49, 49, 49, 44, 49, 49, 52, 44, 49, 48, 56, 44, 49, 48, 48, 93,
          125
        ]),
        'json'
      )
    ).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  }),

  it('should decode PEM encoded chunks correctly', () => {
    expect(
      decode(
        Uint8Array.from([
          45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 77, 89, 32, 77, 69, 83,
          83, 65, 71, 69, 45, 45, 45, 45, 45, 10, 83, 71, 86, 115, 98, 71, 56,
          103, 86, 50, 57, 121, 98, 71, 81, 61, 10, 45, 45, 45, 45, 45, 69, 78,
          68, 32, 77, 89, 32, 77, 69, 83, 83, 65, 71, 69, 45, 45, 45, 45, 45
        ]),
        'pem'
      )
    ).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  }),

  it('should decode UTF-8 chunks correctly', () => {
    const view = Uint8Array.from([
      64, 194, 128, 224, 160, 128, 240, 144, 128, 128
    ])
    expect(decode(view)).toEqual(view)
  }),

  it('should decode strings correctly', () => {
    const view = Uint8Array.from([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
    ])
    expect(decode('SGVsbG8gV29ybGQ=', 'base64')).toEqual(view)
    expect(decode('SGVsbG8gV29ybGQ', 'base64url')).toEqual(view)
    expect(decode('48656c6c6f20576f726c64', 'hex')).toEqual(view)
    expect(
      decode(
        '{"type":"Buffer","data":[72,101,108,108,111,32,87,111,114,108,100]}',
        'json'
      )
    ).toEqual(view)
    expect(
      decode(
        `-----BEGIN MY MESSAGE-----
        SGVsbG8gV29ybGQ=
        -----END MY MESSAGE-----`,
        'pem'
      )
    ).toEqual(view)
    expect(decode('Hello World', 'utf8')).toEqual(view)
  }),

  it('should handle invalid encodings gracefully', () => {
    expect(
      decode(
        Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]),
        'hubba'
      )
    ).toEqual(Uint8Array.from([]))
  })
])
