#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INCLUDE_DIR="${ROOT_DIR}/include"
TARGET_DIR="${ROOT_DIR}/target"
BUILD_DIR="${TARGET_DIR}/ffi"
HEADER_DIR="${BUILD_DIR}/include"

CARGO_ARGS="+nightly rustc -Z build-std --profile ffi --features ffi --crate-type=staticlib --quiet"

if [ $# -eq 0 ]
then
    cargo ${CARGO_ARGS}
else
    BUILD_DIR="${TARGET_DIR}/${1}/ffi"
    HEADER_DIR="${BUILD_DIR}/include"
    cargo ${CARGO_ARGS} --target ${1}
fi

mkdir -p "${HEADER_DIR}"
cp "${INCLUDE_DIR}/stedy.h" "${HEADER_DIR}"

echo "${BUILD_DIR}/libstedy.a"
echo "${HEADER_DIR}"

