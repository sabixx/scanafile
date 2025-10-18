# build-release.sh
set -euo pipefail

APP="scanafile"                                # binary name
PKG_DIR="dist"
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.1.0)}"
LDFLAGS="-s -w"                                # strip symbols
# add version to the binary (if you have 'var version string' in code)
# LDFLAGS="$LDFLAGS -X 'main.version=$VERSION'"

# Common targets: linux/darwin/windows x86_64 + arm64
targets=(
  "linux/amd64"   # x86_64 Linux (Amazon Linux/Ubuntu on Intel)
  "linux/arm64"   # Graviton
  "darwin/amd64"  # Intel macOS
  "darwin/arm64"  # Apple Silicon
  "windows/amd64" # Intel/AMD Windows
  "windows/arm64" # Windows on ARM (Server 2022/Win11 on ARM64)
)

echo "==> Cleaning ${PKG_DIR}"
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"

build_one () {
  local GOOS="$1" GOARCH="$2"
  echo "==> Building ${APP} ${VERSION} for ${GOOS}/${GOARCH}"

  local ext=""
  [[ "$GOOS" == "windows" ]] && ext=".exe"

  local outdir="${PKG_DIR}/${APP}_${VERSION}_${GOOS}_${GOARCH}"
  mkdir -p "$outdir"

  # Build (static-ish; all your deps are pure Go)
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "$LDFLAGS" -o "${outdir}/${APP}${ext}" .

  # Add helpful extras
  [[ -f README.MD ]] && cp README.MD "$outdir"/ || true
  [[ -f LICENSE ]]   && cp LICENSE   "$outdir"/ || true
  [[ -f pwd-list.txt ]] && cp pwd-list.txt "$outdir"/ || true

  # Package
  if [[ "$GOOS" == "windows" ]]; then
    (cd "${PKG_DIR}" && zip -rq "${APP}_${VERSION}_${GOOS}_${GOARCH}.zip" "$(basename "$outdir")")
  else
    (cd "${PKG_DIR}" && tar -czf "${APP}_${VERSION}_${GOOS}_${GOARCH}.tar.gz" "$(basename "$outdir")")
  fi

  # Optional: leave raw folder; you can remove to save space
}

for t in "${targets[@]}"; do
  IFS=/ read GOOS GOARCH <<<"$t"
  build_one "$GOOS" "$GOARCH"
done

echo "==> Checksums"
cd "${PKG_DIR}"
# macOS: brew install coreutils to have sha256sum; otherwise use shasum -a 256
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum *.zip *.tar.gz > "SHA256SUMS_${VERSION}.txt"
else
  shasum -a 256 *.zip *.tar.gz > "SHA256SUMS_${VERSION}.txt"
fi

echo "==> Done. Artifacts in $(pwd):"
ls -lh
