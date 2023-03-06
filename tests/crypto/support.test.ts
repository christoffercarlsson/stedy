import { getCiphers, getCurves, getHashes } from '../../src'

describe('Support', () => {
  it('should return a list of supported ciphers', () => {
    const ciphers = [
      'AES-128-CBC',
      'AES-128-CTR',
      'AES-128-GCM',
      'AES-192-CBC',
      'AES-192-CTR',
      'AES-192-GCM',
      'AES-256-CBC',
      'AES-256-CTR',
      'AES-256-GCM'
    ]
    expect(getCiphers()).toEqual(ciphers)
  })

  it('should return a list of supported elliptic curves', () => {
    const curves = ['P-256', 'P-384', 'P-521', 'Curve25519']
    expect(getCurves()).toEqual(curves)
  })

  it('should return a list of supported hash algorithms', () => {
    const hashes = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
    expect(getHashes()).toEqual(hashes)
  })
})
