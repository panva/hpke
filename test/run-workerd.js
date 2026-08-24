import { getUnsupportedAlgorithms } from './run.js'
import { runRuntimeTests } from './run-runtime.js'

export default {
  test() {
    return runRuntimeTests({ unsupported: getUnsupportedAlgorithms(), readmeRuntime: 'workerd' })
  },
}
