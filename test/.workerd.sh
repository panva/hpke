#!/bin/bash

COMPATIBILITY_DATE=$(node -p "const d = require('workerd').compatibilityDate, t = new Date().toISOString().slice(0,10); d > t ? t : d")

echo "Using compatibility date $COMPATIBILITY_DATE"

node --run build

rm -f test/run-workerd.bundle.js
./node_modules/.bin/esbuild \
  --log-level=warning \
  --format=esm \
  --bundle \
  --target=esnext \
  --alias:hpke=./index.js \
  --loader:.md=text \
  --outfile=test/run-workerd.bundle.js \
  test/run-workerd.js

rm -f test/.workerd.capnp
cat <<EOT > $(pwd)/test/.workerd.capnp
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .tapWorker),
  ],
);

const tapWorker :Workerd.Worker = (
  modules = [
    (name = "worker", esModule = embed "run-workerd.bundle.js")
  ],
  compatibilityDate = "$COMPATIBILITY_DATE",
);
EOT

workerd test --verbose $(pwd)/test/.workerd.capnp
