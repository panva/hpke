#!/bin/bash

LLRT_BIN=${LLRT_BIN:-llrt}

echo "Using $("$LLRT_BIN" --version)"

node --run build

rm -f test/run-llrt.bundle.js
./node_modules/.bin/esbuild \
  --log-level=warning \
  --format=esm \
  --bundle \
  --target=es2023 \
  --alias:hpke=./index.js \
  --loader:.md=text \
  --outfile=test/run-llrt.bundle.js \
  test/run-llrt.js

"$LLRT_BIN" test/run-llrt.bundle.js
