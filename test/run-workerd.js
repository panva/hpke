import {
  findReadmeSupportMismatches,
  formatReadmeSupportMismatch,
  getUnsupportedAlgorithms,
  runAlgorithmTests,
  runVectorValidation,
} from './run.js'

import * as HPKE from '../index.js'
import * as Noble from '../examples/noble-suite/index.js'

import readme from '../README.md'
import vectors from './vectors.json'
import vectorsPq from './vectors-pq.json'
import vectorsDnhpke from './vectors-dnhpke.json'

export default {
  async test() {
    const unsupported = getUnsupportedAlgorithms()
    const { results, passingImplementations } = await runAlgorithmTests({
      HPKE,
      Noble,
      unsupported,
    })

    console.log(`Algorithm tests: ${results.passed}/${results.total} passed`)
    console.log(`  Expected failures: ${results.expectedFailures}`)
    console.log(`  Unexpected failures: ${results.unexpectedFailures}`)
    console.log(`  Unexpected passes: ${results.unexpectedPasses}`)

    if (results.unexpectedFailures > 0) {
      const failed = results.tests.filter((t) => t.status === 'failed' && !t.expectedToFail)
      for (const t of failed) {
        console.log(`  UNEXPECTED FAILURE: ${t.name} — ${t.error}`)
      }
      throw new Error(`${results.unexpectedFailures} unexpected test failure(s)`)
    }

    if (results.unexpectedPasses > 0) {
      const passed = results.tests.filter((t) => t.status === 'passed' && t.expectedToFail)
      for (const t of passed) {
        console.log(`  UNEXPECTED PASS: ${t.name}`)
      }
      throw new Error(`${results.unexpectedPasses} unexpected test pass(es)`)
    }

    const readmeMismatches = findReadmeSupportMismatches({ results, readme, runtime: 'workerd' })

    if (readmeMismatches.length > 0) {
      for (const mismatch of readmeMismatches) {
        console.log(`  README MISMATCH: ${formatReadmeSupportMismatch(mismatch)}`)
      }
      throw new Error(`${readmeMismatches.length} README.md support mismatch(es)`)
    }

    const vectorResults = await runVectorValidation({
      HPKE,
      vectors,
      vectorsPq,
      vectorsDnhpke,
      passingImplementations,
    })

    console.log(`Vector validation: ${vectorResults.passed}/${vectorResults.total} passed`)

    if (vectorResults.failed > 0) {
      throw new Error(`${vectorResults.failed} vector validation failure(s)`)
    }
  },
}
