import { describe, it, expect } from '../../src/test.js'
import { getCurves } from '../../src/crypto.js'

export default describe('getCurves', () =>
  it('should return a list of supported elliptic curves', async () => {
    const curves = ['P-256', 'P-384', 'P-521', 'Curve25519', 'Curve448']
    expect(getCurves()).toEqual(curves)
  }))
