import { getCurves } from '../../src/crypto'

describe('getCurves', () => {
  it('should return a list of supported elliptic curves', () => {
    const curves = ['P-256', 'P-384', 'P-521', 'Curve25519']
    expect(getCurves()).toEqual(curves)
  })
})
