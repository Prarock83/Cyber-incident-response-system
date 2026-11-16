#!/usr/bin/env bash
# Package the CIRS Chrome extension for local install / Chrome Web Store upload.
# Usage: bash scripts/package-extension.sh
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(node -p "require('./extension/manifest.json').version")"
OUT_DIR="dist"
OUT="${OUT_DIR}/cirs-extension-v${VERSION}.zip"

mkdir -p "$OUT_DIR"
rm -f "$OUT"

# Only runtime files: manifest, source, icons. No node_modules, no docs.
(cd extension && zip -r -q "../${OUT}" . -x '*.DS_Store' -x '*__MACOSX*')

echo "Packaged ${OUT}"
unzip -l "$OUT" | tail -n 5
echo
echo "Local testing: chrome://extensions → Developer mode → Load unpacked → select ./extension"
echo "Store upload:  https://chrome.google.com/webstore/devconsole → upload ${OUT}"
