#!/usr/bin/env bash

set -euo pipefail

cmake --preset default -DXNIFF_ENABLE_ARM64E=ON
cmake --build --preset default
