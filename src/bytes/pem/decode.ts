import { base64Decode } from '../base/decode'

const decode = (str: string) =>
  base64Decode(str.replace(/-{5}(BEGIN|END) [^-]+-{5}/gim, ''))

export default decode
