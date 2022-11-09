import { alloc } from '../../src/chunk'

describe('alloc', () => {
  it('should allocate a new zero-filled chunk with a given size', () => {
    expect(alloc(4)).toEqual(Uint8Array.from([0, 0, 0, 0]))
  })

  it('should return an empty chunk on invalid input', () => {
    expect(alloc(null)).toEqual(Uint8Array.from([]))
  })
})
