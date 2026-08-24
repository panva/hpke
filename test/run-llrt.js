import { runRuntimeTests } from './run-runtime.js'

try {
  await runRuntimeTests({ unsupported: { kem: [], kdf: [], aead: [] } })
} catch (error) {
  console.error(error)
  process.exitCode = 1
}
