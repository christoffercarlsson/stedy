import { splitString } from '../utils'

const decode = (str: string) =>
  Uint8Array.from(
    splitString(str, 2)
      .map((s: string) => Number.parseInt(s, 16))
      .flat()
  )

export default decode
