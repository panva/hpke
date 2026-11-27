#!/bin/bash

ELECTRON_BIN=${ELECTRON_BIN:-"$(pwd)/test/electron/node_modules/.bin/electron"}

ELECTRON_RUN_AS_NODE=1 exec "$ELECTRON_BIN" --test --no-warnings "$@"
