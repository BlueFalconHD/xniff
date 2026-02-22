#!/usr/bin/env bash
set -euo pipefail

# Ensure clang is resolved via the active Xcode/SDK.
exec /usr/bin/xcrun --sdk macosx clang "$@"
