import { describe, it, expect } from '../../dist/test.js'
import { trimLeft, trimRight } from '../../dist/chunk.js'

export default describe('trim', () => {
  const view = Uint8Array.from([1, 2, 3])

  return [
    it('should trim leading zeroes', () => {
      expect(trimLeft(Uint8Array.from([0, 0, 0, 1, 2, 3]))).toEqual(view)
    }),

    it('should trim trailing zeroes', () => {
      expect(trimRight(Uint8Array.from([1, 2, 3, 0, 0, 0]))).toEqual(view)
    }),

    it('should trim leading bytes', () => {
      expect(trimLeft(Uint8Array.from([2, 2, 2, 1, 2, 3]), 2)).toEqual(view)
    }),

    it('should trim trailing bytes', () => {
      expect(trimRight(Uint8Array.from([1, 2, 3, 255, 255, 255]), 255)).toEqual(
        view
      )
    }),

    it('should treat invalid byte values as zero', () => {
      const left = Uint8Array.from([0, 0, 0, 1, 2, 3])
      const right = Uint8Array.from([1, 2, 3, 0, 0, 0])
      expect(trimLeft(left, -1)).toEqual(view)
      expect(trimLeft(left, 256)).toEqual(view)
      expect(trimRight(right, -1)).toEqual(view)
      expect(trimRight(right, 256)).toEqual(view)
    })
  ]
})
