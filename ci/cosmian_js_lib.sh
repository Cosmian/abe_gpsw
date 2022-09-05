#!/bin/sh
set -exu

# These tests has to be executed if no breaking has been made.
# Otherwise we know in advance that these tests will fail.
source ci/detect_breaking_changes.sh

if [ "$DO_TEST" = "1" ]; then
  git clone https://github.com/Cosmian/cosmian_js_lib.git
  cp -r pkg/* cosmian_js_lib/tests/wasm_lib/abe/gpsw/
  cd cosmian_js_lib
  npm install jest
  npm test
fi
