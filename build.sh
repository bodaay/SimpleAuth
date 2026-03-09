#!/usr/bin/env bash
set -euo pipefail

APP="simpleauth"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}"
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"
OUT_DIR="dist"

# Platforms: os/arch pairs
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

echo "Building ${APP} ${VERSION}"
echo "---"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  output="${OUT_DIR}/${APP}-${GOOS}-${GOARCH}"
  if [ "${GOOS}" = "windows" ]; then
    output="${output}.exe"
  fi

  echo "  ${GOOS}/${GOARCH} -> ${output}"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
    -ldflags "${LDFLAGS}" \
    -trimpath \
    -o "${output}" \
    .
done

echo "---"

# Generate checksums
cd "${OUT_DIR}"
if command -v sha256sum &>/dev/null; then
  sha256sum ${APP}-* > checksums.txt
elif command -v shasum &>/dev/null; then
  shasum -a 256 ${APP}-* > checksums.txt
fi
cd ..

echo "Done. Artifacts in ${OUT_DIR}/"
ls -lh "${OUT_DIR}/"
