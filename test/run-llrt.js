import { runRuntimeTests } from './run-runtime.js'
import { getUnsupportedAlgorithms } from './run.js'

try {
  await runRuntimeTests({ unsupported: getUnsupportedAlgorithms() })
} catch (error) {
  console.error(error)
  process.exitCode = 1
}
