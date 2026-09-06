#!/usr/bin/env bash
#
# Build platform-tagged Python wheels for the caniac (codeanalyzer-iac) binary.
#
# For each target: cross-compile the binary with the Go toolchain, build a (pure)
# wheel with hatchling, then retag it from `py3-none-any` to the matching platform
# tag with `wheel tags`. The binary is python-agnostic, so each platform needs
# exactly one wheel (py3-none-<platform>), not one per Python version.
#
# Requirements on the build host:
#   - go              (the version in go.mod) -- cross-compiles all targets from
#                     one host because the analyzer is CGO-free (CGO_ENABLED=0)
#   - python -m pip install build wheel hatchling twine
#     (hatchling is the build backend; --no-isolation means it must be installed)
#
# Usage:
#   ./build_wheels.sh           # build all targets into ./dist
#   twine upload dist/*.whl     # publish
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"          # codeanalyzer-iac repo root (has go.mod)
# Version comes from the environment (the release workflow sets it from the git
# tag); the literal is only a local-dev fallback. It is written into __init__.py,
# which is hatch's single source of truth for the wheel version, and stamped into
# the binary as main.version, which is what `caniac --version` prints and what
# every analysis document carries as analyzer.version.
PKG_VERSION="${PKG_VERSION:-0.1.0}"

# The same shape the release workflow requires of a tag. It has to be an already
# normalized PEP 440 version, because the wheel filename below is spelled out
# rather than read back from hatchling -- 0.1.0-dev or 0.1.0-rc1 would be
# normalized to something else and the `wheel tags` call would miss the file.
if [[ ! "$PKG_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?$ ]]; then
  echo "PKG_VERSION='$PKG_VERSION' is not a normalized PEP 440 release version." >&2
  echo "Use X.Y.Z, optionally with aN, bN or rcN: 0.1.0, 0.1.0rc1." >&2
  echo "Hint: 'make wheels' needs VERSION set, e.g. make wheels VERSION=0.1.0rc1." >&2
  exit 1
fi

WHEEL_STEM="codeanalyzer_iac-${PKG_VERSION}-py3-none-any.whl"
BIN_DIR="$HERE/src/codeanalyzer_iac/_bin"
INIT_PY="$HERE/src/codeanalyzer_iac/__init__.py"

# Remove built binaries from _bin/ but keep the tracked .gitignore (and the dir),
# so a local build leaves the working tree pristine.
clean_bin() { mkdir -p "$BIN_DIR"; find "$BIN_DIR" -mindepth 1 ! -name '.gitignore' -delete; }

# Stamp $PKG_VERSION into __init__.py for the build, restoring the original on
# exit so the working tree stays pristine (mirrors the _bin cleanup below).
ORIG_INIT="$(cat "$INIT_PY")"   # $(...) strips the trailing newline; restore re-adds it
restore_init() { printf '%s\n' "$ORIG_INIT" > "$INIT_PY"; }
trap restore_init EXIT
python - "$INIT_PY" "$PKG_VERSION" <<'PY'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path).read()
new, n = re.subn(r'__version__ = "[^"]*"', f'__version__ = "{version}"', text)
if n != 1:
    raise SystemExit(f"expected exactly one __version__ assignment in {path}, found {n}")
open(path, "w").write(new)
print(f">>> stamped __version__ = {version}")
PY

# "GOOS/GOARCH" : "wheel platform tag". The Go binaries are static (CGO_ENABLED=0),
# so the Linux ones satisfy manylinux_2_17 with no shared-library dependencies at all.
TARGETS=(
  "darwin/arm64:macosx_11_0_arm64"
  "darwin/amd64:macosx_11_0_x86_64"
  "linux/amd64:manylinux_2_17_x86_64"
  "linux/arm64:manylinux_2_17_aarch64"
  "windows/amd64:win_amd64"
)

rm -rf "$HERE/dist"
mkdir -p "$HERE/dist"

# The wheel's long description (the PyPI page) is the repo root README — copy it in so there is a
# single source of truth. It is gitignored and removed on exit (see cleanup) to keep the tree pristine.
cp "$REPO_ROOT/README.md" "$HERE/README.md"

for entry in "${TARGETS[@]}"; do
  target="${entry%%:*}"
  plat="${entry##*:}"
  goos="${target%%/*}"
  goarch="${target##*/}"
  ext=""
  [[ "$goos" == windows ]] && ext=".exe"

  echo ">>> [$target] compiling -> wheel ($plat)"

  clean_bin

  # -trimpath keeps the build reproducible; -s -w drops the symbol table and DWARF,
  # which is most of the binary size and nothing a released analyzer needs.
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w -X main.version=$PKG_VERSION" \
        -o "$BIN_DIR/caniac$ext" ./cmd/codeanalyzer-iac )

  # Build a pure wheel (py3-none-any), then retag to the platform.
  python -m build --wheel --no-isolation -o "$HERE/dist" "$HERE"
  python -m wheel tags --remove --platform-tag "$plat" "$HERE/dist/$WHEEL_STEM"
done

# Clean the working binary + copied README so the tree stays pristine.
clean_bin
rm -f "$HERE/README.md"

echo
echo ">>> Built wheels:"
ls -lh "$HERE/dist"/*.whl
echo
echo "Publish with:  twine upload $HERE/dist/*.whl"
