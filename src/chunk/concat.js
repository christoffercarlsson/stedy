import getBytes from './get-bytes'

const concat = (chunks) => {
  const views = Array.isArray(chunks) ? chunks : []
  return Uint8Array.from(views.map((view) => getBytes(view)).flat())
}

export default concat
