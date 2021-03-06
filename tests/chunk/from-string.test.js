import { describe, it, expect } from '../../dist/test.js'
import { fromString } from '../../dist/chunk.js'

export default describe('fromString', () => [
  it('should decode Base 64 encoded strings correctly', () => {
    expect(fromString('HVn8UCmEQ6FRu5+lwpk/VA==', 'base64')).toEqual(
      Uint8Array.from([
        29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
      ])
    )
  }),

  it('should reject invalid Base 64 encoded strings', () => {
    expect(fromString('HVn8UCmEQ6FRu5-lwpk_VA==', 'base64')).toEqual(
      Uint8Array.from([])
    )
    expect(fromString('HVn8UCmEQ6FRu5+lwpk/VA==', 'base64url')).toEqual(
      Uint8Array.from([])
    )
    expect(fromString('HVn8U=CmEQ6FRu5+lwpk/VA==', 'base64')).toEqual(
      Uint8Array.from([])
    )
    expect(fromString('HVn8U=CmEQ6FRu5-lwpk_VA==', 'base64url')).toEqual(
      Uint8Array.from([])
    )
    expect(fromString('Hej och hå', 'base64')).toEqual(Uint8Array.from([]))
    expect(fromString('Hej och hå', 'base64url')).toEqual(Uint8Array.from([]))
    expect(fromString('SGVsbG8gV29yb', 'base64')).toEqual(Uint8Array.from([]))
    expect(fromString('SGVsbG8gV29yb', 'base64url')).toEqual(
      Uint8Array.from([])
    )
  }),

  it('should handle padding correctly when decoding Base 64 strings', () => {
    expect(fromString('SGVsbG8gV29ybGQ=', 'base64')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
    expect(fromString('SGVsbG8gV29ybA==', 'base64')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  }),

  it('should handle unpadded Base 64 strings gracefully', () => {
    expect(fromString('SGVsbG8gV29ybGQ', 'base64')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
    expect(fromString('SGVsbG8gV29ybA', 'base64')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108])
    )
  }),

  it('should handle whitespace correctly when decoding Base 64 strings', () => {
    expect(fromString('SG\tVsbG8\r\ngV29yb GQh', 'base64')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33])
    )
  }),

  it('should decode URL safe Base 64 encoded strings correctly', () => {
    const view = Uint8Array.from([
      29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
    ])
    expect(fromString('HVn8UCmEQ6FRu5-lwpk_VA==', 'base64url')).toEqual(view)
    expect(fromString('HVn8UCmEQ6FRu5-lwpk_VA', 'base64url')).toEqual(view)
  }),

  it('should decode hexadecimal strings correctly', () => {
    expect(fromString('48656c6c6f20576f726c64', 'hex')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  }),

  it('should decode JSON correctly', () => {
    const view = Uint8Array.from([
      72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
    ])
    expect(
      fromString(
        '{"type":"Buffer","data":[72,101,108,108,111,32,87,111,114,108,100]}',
        'json'
      )
    ).toEqual(view)
  }),

  it('should decode PEM encoded strings correctly', () => {
    expect(
      fromString(
        `-----BEGIN MY MESSAGE-----
U3BpY3kgamFsYXBlbm8gYmFjb24gaXBzdW0gZG9sb3IgYW1ldCBmaWxldCBtaWdu
b24gcGlnIHRvbmd1ZSBzaG9ydCBsb2luIHNob3VsZGVyIG1lYXRiYWxs
-----END MY MESSAGE-----`,
        'pem'
      )
    ).toEqual(
      Uint8Array.from([
        83, 112, 105, 99, 121, 32, 106, 97, 108, 97, 112, 101, 110, 111, 32, 98,
        97, 99, 111, 110, 32, 105, 112, 115, 117, 109, 32, 100, 111, 108, 111,
        114, 32, 97, 109, 101, 116, 32, 102, 105, 108, 101, 116, 32, 109, 105,
        103, 110, 111, 110, 32, 112, 105, 103, 32, 116, 111, 110, 103, 117, 101,
        32, 115, 104, 111, 114, 116, 32, 108, 111, 105, 110, 32, 115, 104, 111,
        117, 108, 100, 101, 114, 32, 109, 101, 97, 116, 98, 97, 108, 108
      ])
    )
  }),

  it('should decode UTF-8 strings correctly', () => {
    expect(fromString(String.fromCodePoint(64, 128, 2048, 65536))).toEqual(
      Uint8Array.from([64, 194, 128, 224, 160, 128, 240, 144, 128, 128])
    )
  }),

  it('should handle invalid input gracefully', () => {
    expect(fromString(undefined, 'base64')).toEqual(Uint8Array.from([]))
    expect(fromString(undefined, 'base64url')).toEqual(Uint8Array.from([]))
    expect(fromString(undefined, 'hex')).toEqual(Uint8Array.from([]))
    expect(fromString(undefined, 'json')).toEqual(Uint8Array.from([]))
    expect(fromString(undefined, 'pem')).toEqual(Uint8Array.from([]))
    expect(fromString(undefined, 'utf8')).toEqual(Uint8Array.from([]))
    expect(fromString()).toEqual(Uint8Array.from([]))
    expect(fromString({})).toEqual(Uint8Array.from([]))
    expect(
      fromString(
        '{"type":"Uint8Array","data":[256,1024,108,108,111,32,87,111,114,108,100]}',
        'json'
      )
    ).toEqual(Uint8Array.from([]))
    expect(
      fromString(
        '{"type":"hubba","data":[72,101,108,108,111,32,87,111,114,108,100]}',
        'json'
      )
    ).toEqual(Uint8Array.from([]))
    expect(fromString('"hubba"', 'json')).toEqual(Uint8Array.from([]))
  }),

  it('should handle invalid encodings gracefully', () => {
    expect(fromString('Hello World', 'hubba')).toEqual(Uint8Array.from([]))
  })
])
