import { describe, it, expect } from '../../dist/test.js'
import { toString } from '../../dist/chunk.js'

export default describe('toString', () => [
  it('should produce a correct Base 64 representation of a given chunk', () => {
    expect(
      toString(
        Uint8Array.from([
          29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
        ]),
        'base64'
      )
    ).toEqual('HVn8UCmEQ6FRu5+lwpk/VA==')
  }),

  it('should produce a correct URL safe Base 64 representation of a given chunk', () => {
    expect(
      toString(
        Uint8Array.from([
          29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
        ]),
        'base64url'
      )
    ).toEqual('HVn8UCmEQ6FRu5-lwpk_VA')
  }),

  it('should handle Base 64 padding correctly when encoding', () => {
    expect(
      toString(
        Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]),
        'base64'
      )
    ).toEqual('SGVsbG8gV29ybGQ=')
    expect(
      toString(
        Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108]),
        'base64'
      )
    ).toEqual('SGVsbG8gV29ybA==')
  }),

  it('should produce a correct hexadecimal representation of a given chunk', () => {
    expect(
      toString(
        Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]),
        'hex'
      )
    ).toEqual('48656c6c6f20576f726c64')
  }),

  it('should produce a correct JSON representation of a given chunk', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    expect(toString(Uint8Array.from(bytes), 'json')).toEqual(
      JSON.stringify(Buffer.from(bytes))
    )
  }),

  it('should produce a correct PEM representation of a given chunk', () => {
    const view = Uint8Array.from([
      83, 112, 105, 99, 121, 32, 106, 97, 108, 97, 112, 101, 110, 111, 32, 98,
      97, 99, 111, 110, 32, 105, 112, 115, 117, 109, 32, 100, 111, 108, 111,
      114, 32, 97, 109, 101, 116, 32, 102, 105, 108, 101, 116, 32, 109, 105,
      103, 110, 111, 110, 32, 112, 105, 103, 32, 116, 111, 110, 103, 117, 101,
      32, 115, 104, 111, 114, 116, 32, 108, 111, 105, 110, 32, 115, 104, 111,
      117, 108, 100, 101, 114, 32, 109, 101, 97, 116, 98, 97, 108, 108
    ])
    expect(toString(view, 'pem', 'my-message'))
      .toEqual(`-----BEGIN MY MESSAGE-----
U3BpY3kgamFsYXBlbm8gYmFjb24gaXBzdW0gZG9sb3IgYW1ldCBmaWxldCBtaWdu
b24gcGlnIHRvbmd1ZSBzaG9ydCBsb2luIHNob3VsZGVyIG1lYXRiYWxs
-----END MY MESSAGE-----`)
  }),

  it('should produce a correct UTF-8 representation of a given chunk', () => {
    expect(
      toString(
        Uint8Array.from([64, 194, 128, 224, 160, 128, 240, 144, 128, 128])
      )
    ).toEqual(String.fromCodePoint(64, 128, 2048, 65536))
  }),

  it('should handle invalid input gracefully', () => {
    expect(toString(undefined, 'base64')).toEqual('')
    expect(toString(undefined, 'base64url')).toEqual('')
    expect(toString(undefined, 'json')).toEqual('')
    expect(toString(undefined, 'hex')).toEqual('')
    expect(toString(undefined, 'pem')).toEqual('')
    expect(toString(undefined, 'utf8')).toEqual('')
    expect(toString()).toEqual('')
    expect(toString('hubba')).toEqual('')
    expect(toString({})).toEqual('')
  }),

  it('should handle invalid encodings gracefully', () => {
    expect(
      toString(
        Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]),
        'hubba'
      )
    ).toEqual('')
  })
])
