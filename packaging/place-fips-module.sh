#!/usr/bin/env bash
# Puts the validated AWS-LC FIPS module beside the binaries that load it.
#
# Only Apple targets need this. `aws-lc-fips-sys` links the module statically
# on Linux and BSD and dynamically everywhere else, so on macOS the build
# leaves a `libaws_lc_fips_<version>_crypto.dylib` under the build script's
# output directory and stamps `@rpath/...` into everything that links it.
# `.cargo/config.toml` supplies the matching `@loader_path` rpath; this script
# supplies the other half by copying the module to where `@loader_path` looks.
#
# Run it after `cargo build`/`cargo nextest --no-run` and before running
# anything. On a non-Apple host it does nothing and says so, so a caller may
# run it unconditionally.
#
#   packaging/place-fips-module.sh <build-dir> [destination ...]
#
# `build-dir` is the profile directory to search, e.g. `target/release` or
# `target/aarch64-apple-darwin/release`. Destinations default to that
# directory and its `deps/` — the daemon the sandbox re-execs lives in the
# first, the test binaries in the second. A release pass passes its staging
# directory as well.
#
# Exits non-zero when it is on Apple and cannot find the module, because the
# alternative is a binary that builds and then dies at startup with
# "Library not loaded: @rpath/libaws_lc_fips_...dylib".
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "not Apple: the FIPS module is linked statically here, nothing to place"
  exit 0
fi

build_dir="${1:?usage: place-fips-module.sh <build-dir> [destination ...]}"
shift
destinations=("$@")
if [ "${#destinations[@]}" -eq 0 ]; then
  destinations=("$build_dir" "$build_dir/deps")
fi

# Under `<build-dir>/build/aws-lc-fips-sys-<hash>/out/`, but the hash and the
# depth below `out/` are both cargo's business rather than ours.
module="$(find "$build_dir/build" -type f -name 'libaws_lc_fips_*_crypto.dylib' 2>/dev/null | head -n 1)"
if [ -z "$module" ]; then
  echo "::error::no libaws_lc_fips_*_crypto.dylib under $build_dir/build" >&2
  echo "a FIPS build on Apple links the module dynamically; without it the" >&2
  echo "binaries here cannot start. Has the build run?" >&2
  exit 1
fi

echo "module: $module"
for destination in "${destinations[@]}"; do
  if [ ! -d "$destination" ]; then
    echo "  skipping $destination (not a directory)"
    continue
  fi
  cp -f "$module" "$destination/"
  echo "  placed in $destination"
done
