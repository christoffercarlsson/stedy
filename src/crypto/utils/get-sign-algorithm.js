import {
  ALGORITHM_ECDSA,
  ALGORITHM_NODE_ED25519,
  ALGORITHM_NODE_ED448,
  CURVE_CURVE25519,
  CURVE_CURVE448
} from '../constants.js'

const getSignAlgorithm = (curve, hash) => {
  switch (curve) {
    case CURVE_CURVE448:
      return ALGORITHM_NODE_ED448
    case CURVE_CURVE25519:
      return ALGORITHM_NODE_ED25519
    default:
      return { name: ALGORITHM_ECDSA, hash }
  }
}

export default getSignAlgorithm
