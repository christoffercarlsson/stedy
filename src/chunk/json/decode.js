const parseJSON = (string) => {
  try {
    return JSON.parse(string)
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error
    }
    return {}
  }
}

const isValidData = (data) =>
  Array.isArray(data) &&
  data.every((byte) => Number.isInteger(byte) && byte >= 0 && byte < 256)

const isValidType = (type) => type === 'Buffer'

const decode = (string) => {
  const { type, data } = parseJSON(string)
  return Uint8Array.from(isValidType(type) && isValidData(data) ? data : [])
}

export default decode
