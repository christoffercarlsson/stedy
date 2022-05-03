import { describe, it, expect } from '../../dist/test.js'
import { alloc } from '../../dist/chunk.js'

export default describe('alloc', () => [
  it('should allocate a new zero-filled chunk with a given size', () => {
    expect(alloc(4)).toEqual(Uint8Array.from([0, 0, 0, 0]))
  }),

  it('should allocate an empty chunk on invalid input', () => {
    expect(alloc('hubba')).toEqual(Uint8Array.from([]))
  })
])
