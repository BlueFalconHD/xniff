#!/usr/bin/env bash

set -euo pipefail

cmake --preset default -DXNIFF_ENABLE_ARM64E=ON
cmake --build --preset default
xniff_swift_cache="Viewer/.build/module-cache"
mkdir -p "$xniff_swift_cache"
SWIFT_MODULECACHE_PATH="$xniff_swift_cache" \
CLANG_MODULE_CACHE_PATH="$xniff_swift_cache" \
swift build --disable-sandbox --package-path Viewer -c release
cp Viewer/.build/release/xniff-viewer build/xniff-viewer
cp Viewer/.build/release/xniff-print build/xniff-print
xniff_viewer_app="build/xniff-viewer.app"
mkdir -p "$xniff_viewer_app/Contents/MacOS"
cp Viewer/.build/release/xniff-viewer "$xniff_viewer_app/Contents/MacOS/xniff-viewer"
cp Viewer/Info.plist "$xniff_viewer_app/Contents/Info.plist"
codesign --force --sign - "$xniff_viewer_app"
