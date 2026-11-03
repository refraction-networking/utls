#!/bin/sh
# Build the BoringSSL interop peer OUTSIDE the source tree.
#   BORINGSSL=/path/to/boringssl (with build/libssl.a, build/libcrypto.a)
#   OUT=/path/to/output/dir
# Prints the peer path. Requires clang++ and system zlib.
set -eu
: "${BORINGSSL:?set BORINGSSL to a BoringSSL checkout with a build/ directory}"
: "${OUT:?set OUT to an output directory outside the repository}"
mkdir -p "$OUT"
clang++ -std=c++17 -O2 -I"$BORINGSSL/include" "$(dirname "$0")/peer.cc" \
	"$BORINGSSL/build/libssl.a" "$BORINGSSL/build/libcrypto.a" -lz -lpthread \
	-o "$OUT/utls-bssl-peer"
echo "$OUT/utls-bssl-peer"
