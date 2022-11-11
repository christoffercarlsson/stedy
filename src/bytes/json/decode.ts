const isValidData = (data: number[]) =>
  Array.isArray(data) &&
  data.every((byte) => Number.isInteger(byte) && byte >= 0 && byte < 256)

const isValidType = (type: string) => type === 'Buffer'

const decode = (str: string) => {
  try {
    const { type, data } = JSON.parse(str) as { type: string; data: number[] }
    return Uint8Array.from(isValidType(type) && isValidData(data) ? data : [])
  } catch (error) {
    return Uint8Array.from([])
  }
}

export default decode
