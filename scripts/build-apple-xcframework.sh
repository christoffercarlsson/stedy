#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"
TARGET_DIR="${ROOT_DIR}/target"
XCFRAMEWORK_ARGS=""

OUTPUT_PATH="${TARGET_DIR}/Libstedy.xcframework"

if [ -d "${OUTPUT_PATH}" ]
then
    rm -rf "${OUTPUT_PATH}"
fi

module_map() {
    echo 'module Libstedy {'
    echo '  header "stedy.h"'
    echo '  export *'
    echo '}'
}

build_targets() {
    for target in "$@"
    do
        output=$(. "${SCRIPT_DIR}/build-ffi.sh" ${target})
        library_path=$(echo "$output" | sed -n '1p')
        header_dir=$(echo "$output" | sed -n '2p')
        module_map > "${header_dir}/module.modulemap"
        XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -library ${library_path} -headers ${header_dir}"
    done
}

build_framework() {
    xcodebuild -create-xcframework ${XCFRAMEWORK_ARGS} -output "${OUTPUT_PATH}" > /dev/null
}

echo "Building for macOS..."
build_targets aarch64-apple-darwin

echo "Building for iOS..."
build_targets aarch64-apple-ios aarch64-apple-ios-sim

echo "Building for Mac Catalyst..."
build_targets aarch64-apple-ios-macabi

echo "Building for watchOS..."
build_targets aarch64-apple-watchos aarch64-apple-watchos-sim

echo "Building for tvOS..."
build_targets aarch64-apple-tvos aarch64-apple-tvos-sim

echo "Building for visionOS..."
build_targets aarch64-apple-visionos aarch64-apple-visionos-sim

echo "Building XCFramework..."
build_framework

echo "Done!"

echo "\n${OUTPUT_PATH}"
