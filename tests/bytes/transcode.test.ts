import { Bytes } from '../../src/bytes'

describe('transcode', () => {
  it('should re-encode a given chunk from one encoding to another', () => {
    expect(
      Bytes.from([
        52, 56, 54, 53, 54, 99, 54, 99, 54, 102, 50, 48, 53, 55, 54, 102, 55,
        50, 54, 99, 54, 52
      ]).transcode('hex', 'base64url')
    ).toEqual(
      Bytes.from([
        83, 71, 86, 115, 98, 71, 56, 103, 86, 50, 57, 121, 98, 71, 81
      ])
    )
  })
})
