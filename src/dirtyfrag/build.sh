#!/bin/sh

set -eu
cd "$(dirname "$0")"

./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/honor-root-tool.apk ./honor-root-tool.apk
ls -l ./honor-root-tool.apk
echo "OK: ./honor-root-tool.apk"
