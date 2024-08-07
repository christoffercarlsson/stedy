import { Bytes, createFrom } from '../../src'

describe('toString', () => {
  it('should produce a correct Base 32 representation of a given chunk', () => {
    expect(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]).toString(
        'base32'
      )
    ).toEqual('JBSWY3DPEBLW64TMMQ======')
    expect(Bytes.from([102]).toString('base32')).toEqual('MY======')
    expect(Bytes.from([102, 111]).toString('base32')).toEqual('MZXQ====')
    expect(Bytes.from([102, 111, 111]).toString('base32')).toEqual('MZXW6===')
    expect(Bytes.from([102, 111, 111, 98]).toString('base32')).toEqual(
      'MZXW6YQ='
    )
    expect(Bytes.from([102, 111, 111, 98, 97]).toString('base32')).toEqual(
      'MZXW6YTB'
    )
  })

  it('should produce a correct Base 64 representation of a given chunk', () => {
    expect(
      Bytes.from([
        29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
      ]).toString('base64')
    ).toEqual('HVn8UCmEQ6FRu5+lwpk/VA==')
  })

  it('should produce a correct URL safe Base 64 representation of a given chunk', () => {
    expect(
      Bytes.from([
        29, 89, 252, 80, 41, 132, 67, 161, 81, 187, 159, 165, 194, 153, 63, 84
      ]).toString('base64_url_unpadded')
    ).toEqual('HVn8UCmEQ6FRu5-lwpk_VA')
  })

  it('should handle Base 64 padding correctly when encoding', () => {
    expect(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]).toString(
        'base64'
      )
    ).toEqual('SGVsbG8gV29ybGQ=')
    expect(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108]).toString(
        'base64'
      )
    ).toEqual('SGVsbG8gV29ybA==')
  })

  it('should produce a correct hexadecimal representation of a given chunk', () => {
    expect(
      Bytes.from([
        10, 137, 184, 253, 161, 109, 6, 54, 134, 118, 246, 227, 130, 46, 84, 55
      ]).toString('hex')
    ).toEqual('0a89b8fda16d06368676f6e3822e5437')
  })

  it('should produce a correct JSON representation of a given chunk', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    expect(Bytes.from(bytes).toString('json')).toEqual(
      JSON.stringify(Buffer.from(bytes))
    )
  })

  it('should produce a correct PEM representation of a given chunk', () => {
    const view = Bytes.from([
      83, 112, 105, 99, 121, 32, 106, 97, 108, 97, 112, 101, 110, 111, 32, 98,
      97, 99, 111, 110, 32, 105, 112, 115, 117, 109, 32, 100, 111, 108, 111,
      114, 32, 97, 109, 101, 116, 32, 102, 105, 108, 101, 116, 32, 109, 105,
      103, 110, 111, 110, 32, 112, 105, 103, 32, 116, 111, 110, 103, 117, 101,
      32, 115, 104, 111, 114, 116, 32, 108, 111, 105, 110, 32, 115, 104, 111,
      117, 108, 100, 101, 114, 32, 109, 101, 97, 116, 98, 97, 108, 108
    ])
    expect(view.toString('pem', 'my-message'))
      .toEqual(`-----BEGIN MY MESSAGE-----
U3BpY3kgamFsYXBlbm8gYmFjb24gaXBzdW0gZG9sb3IgYW1ldCBmaWxldCBtaWdu
b24gcGlnIHRvbmd1ZSBzaG9ydCBsb2luIHNob3VsZGVyIG1lYXRiYWxs
-----END MY MESSAGE-----`)
  })

  it('should produce a correct UTF-8 representation of a given chunk', () => {
    expect(
      Bytes.from([64, 194, 128, 224, 160, 128, 240, 144, 128, 128]).toString()
    ).toEqual(String.fromCodePoint(64, 128, 2048, 65536))
  })

  it('should handle invalid input gracefully', () => {
    expect(createFrom(undefined).toString('base64')).toEqual('')
    expect(createFrom(undefined).toString('base64_url')).toEqual('')
    expect(createFrom(undefined).toString('json')).toEqual('')
    expect(createFrom(undefined).toString('hex')).toEqual('')
    expect(createFrom(undefined).toString('pem')).toEqual('')
    expect(createFrom(undefined).toString('utf8')).toEqual('')
    expect(createFrom(undefined).toString()).toEqual('')
    expect(createFrom(null).toString()).toEqual('')
  })

  it('should handle invalid encodings gracefully', () => {
    expect(
      Bytes.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]).toString(
        'hubba'
      )
    ).toEqual('')
  })
})
