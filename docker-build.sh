#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# docker-build.sh - Build SimpleAuth Docker image (linux/amd64)
# and save as dist/simpleauth.tar
#
# Usage:  ./docker-build.sh
# ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION=$(grep 'Version.*=' main.go | head -1 | sed 's/.*"\(.*\)".*/\1/')
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
IMAGE_NAME="simpleauth"
IMAGE_TAG="${IMAGE_NAME}:${VERSION}"
OUTPUT_DIR="${SCRIPT_DIR}/dist"
OUTPUT_FILE="${OUTPUT_DIR}/simpleauth.tar"

mkdir -p "$OUTPUT_DIR"

echo "=== Building SimpleAuth Docker Image ==="
echo "  Version:  ${VERSION}"
echo "  Platform: linux/amd64"
echo "  Output:   ${OUTPUT_FILE}"

docker buildx build \
  --platform linux/amd64 \
  --tag "$IMAGE_TAG" \
  --tag "${IMAGE_NAME}:latest" \
  --build-arg "VERSION=${VERSION}" \
  --build-arg "BUILD_TIME=${BUILD_TIME}" \
  --output "type=docker,dest=${OUTPUT_FILE}" \
  .

SIZE=$(du -sh "$OUTPUT_FILE" | cut -f1)
echo ""
echo "=== Done. ${OUTPUT_FILE} (${SIZE}) ==="
