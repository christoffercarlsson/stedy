import {
  ALGORITHM_ECDSA,
  ALGORITHM_NODE_ED448,
  CURVE_CURVE448
} from '../constants.js'

const getSignAlgorithm = (curve, hash) =>
  curve === CURVE_CURVE448
    ? ALGORITHM_NODE_ED448
    : { name: ALGORITHM_ECDSA, hash }

export default getSignAlgorithm
