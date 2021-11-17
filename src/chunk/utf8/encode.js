const bytesToCharacter = (firstByte, secondByte, thirdByte, fourthByte) => {
  if (fourthByte) {
    return String.fromCodePoint(
      ((firstByte & 15) << 18) |
        ((secondByte & 63) << 12) |
        ((thirdByte & 63) << 6) |
        (fourthByte & 63)
    )
  }
  if (thirdByte) {
    return String.fromCodePoint(
      ((firstByte & 15) << 12) | ((secondByte & 63) << 6) | (thirdByte & 63)
    )
  }
  if (secondByte) {
    return String.fromCodePoint(((firstByte & 31) << 6) | (secondByte & 63))
  }
  return String.fromCodePoint(firstByte)
}

const numberOfBytesNeeded = (firstByte) => {
  if (firstByte > 239) {
    return 4
  }
  if (firstByte > 223) {
    return 3
  }
  if (firstByte > 191) {
    return 2
  }
  return 1
}

const encode = (view) =>
  view
    .reduce((state, byte, index) => {
      const begin = state.length > 0 ? state[state.length - 1][1] : 0
      if (begin > index) {
        return state
      }
      const end = begin + numberOfBytesNeeded(byte)
      return state.concat([[begin, end]])
    }, [])
    .map(([begin, end]) => bytesToCharacter(...view.subarray(begin, end)))
    .join('')

export default encode
