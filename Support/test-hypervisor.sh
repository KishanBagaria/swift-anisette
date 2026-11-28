#!/bin/sh
set -eu

ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/hypervisor.entitlements"
swift build --build-tests ${SWIFT_BUILD_FLAGS:-}
BIN_PATH="$(swift build --show-bin-path ${SWIFT_BUILD_FLAGS:-})"
TEST_BIN="$BIN_PATH/swift-anisettePackageTests.xctest/Contents/MacOS/swift-anisettePackageTests"
SWIFT_BIN="$(xcrun --find swift)"
HELPER_SRC="$(cd "$(dirname "$SWIFT_BIN")/.." && pwd)/libexec/swift/pm/swiftpm-testing-helper"
HELPER_DST="$BIN_PATH/swiftpm-testing-helper-hypervisor"
PLATFORM_FRAMEWORKS="$(xcrun --show-sdk-platform-path)/Developer/Library/Frameworks"
TOOLCHAIN_LIBS="$(cd "$(dirname "$SWIFT_BIN")/.." && pwd)/lib/swift/macosx"

cp "$HELPER_SRC" "$HELPER_DST"
codesign --force --sign - --entitlements "$ENTITLEMENTS" "$HELPER_DST"
exec env DYLD_FRAMEWORK_PATH="$PLATFORM_FRAMEWORKS:$TOOLCHAIN_LIBS${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}" \
    "$HELPER_DST" --test-bundle-path "$TEST_BIN" --testing-library swift-testing "$@"
