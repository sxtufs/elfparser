#!/usr/bin/env bash
# Build the propagation clone fixture into the accuracy fixtures directory.
#
# Usage:  ./build_clones.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to $ELFTRACE_FIXTURES_DIR or /workspace/test_fixtures/accuracy
#
# Requires gcc-aarch64-linux-gnu (installed in CI before tests run).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${ELFTRACE_FIXTURES_DIR:-/workspace/test_fixtures/accuracy}}"
mkdir -p "$OUT_DIR"

CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "ERROR: $CC not found. Install gcc-aarch64-linux-gnu." >&2
    exit 1
fi

OUT="$OUT_DIR/fx_a64_clones.so"
# -fno-ipa-icf: keep the two identical function bodies as separate copies.
# -O2: realistic codegen. Shared/PIC so the ELF has executable PT_LOAD segments.
"$CC" -shared -fPIC -O2 -fno-ipa-icf \
    -o "$OUT" "$HERE/fx_a64_clones.c"

# Sanity: both symbols must be exported and distinct in address.
if ! aarch64-linux-gnu-readelf --dyn-syms "$OUT" | grep -q clone_a; then
    echo "ERROR: clone_a not exported in $OUT" >&2
    exit 1
fi
if ! aarch64-linux-gnu-readelf --dyn-syms "$OUT" | grep -q clone_b; then
    echo "ERROR: clone_b not exported in $OUT" >&2
    exit 1
fi

echo "Built $OUT"
