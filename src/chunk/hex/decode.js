import { splitString } from '../utils.js'

const decode = (string) =>
  Uint8Array.from(
    splitString(string, 2)
      .map((str) => Number.parseInt(str, 16))
      .flat()
  )

export default decode
