import { Chunk, createFrom } from '../../src/bytes'

describe('Chunk', () => {
  it('should create a new chunk from an iterable', () => {
    function* generateBytes() {
      yield 1
      yield 2
      yield 3
    }
    const chunk = Chunk.from(generateBytes(), (byte) => byte * 2)
    expect(chunk.getBytes()).toEqual([2, 4, 6])
  })

  it('should stringify a chunk into a correct JSON representation', () => {
    const bytes = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
    const buffer = Buffer.from(bytes)
    const chunk = createFrom(bytes)
    expect(JSON.stringify(chunk)).toEqual(JSON.stringify(buffer))
  })

  it('should be considered an Uint8Array', () => {
    const chunk = createFrom([1, 2, 3, 4])
    expect(chunk instanceof Uint8Array).toBe(true)
  })

  it('should be considered a view', () => {
    const chunk = createFrom([1, 2, 3, 4])
    expect(ArrayBuffer.isView(chunk)).toBe(true)
  })
})
