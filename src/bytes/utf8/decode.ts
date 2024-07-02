const codePointToBytes = (codePoint: number) => {
  if (codePoint < 128) {
    return [codePoint]
  }
  if (codePoint < 2048) {
    return [(codePoint >> 6) | 192, (codePoint & 63) | 128]
  }
  if (codePoint < 65536) {
    return [
      (codePoint >> 12) | 224,
      ((codePoint >> 6) & 63) | 128,
      (codePoint & 63) | 128
    ]
  }
  return [
    (codePoint >> 18) | 240,
    ((codePoint >> 12) & 63) | 128,
    ((codePoint >> 6) & 63) | 128,
    (codePoint & 63) | 128
  ]
}

const decode = (str: string) =>
  Uint8Array.from(
    [...str]
      .map((character) => codePointToBytes(character.codePointAt(0)))
      .flat()
  )

export default decode
