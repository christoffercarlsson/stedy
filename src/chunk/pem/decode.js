import base64Decode from '../base64/decode.js'

const decode = (string) =>
  base64Decode(string.replace(/-{5}(BEGIN|END) [^-]+-{5}/gim, ''))

export default decode
