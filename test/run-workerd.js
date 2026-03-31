import { runAlgorithmTests, runVectorValidation } from './run.js'

import * as HPKE from '../index.js'
import * as Noble from '../examples/noble-suite/index.js'

import vectors from './vectors.json'
import vectorsPq from './vectors-pq.json'

// Algorithms without native Web Crypto support in workerd
const unsupported = {
  kem: [
    'KEM_DHKEM_X448_HKDF_SHA512',
    'KEM_ML_KEM_512',
    'KEM_ML_KEM_768',
    'KEM_ML_KEM_1024',
    'KEM_MLKEM768_X25519',
    'KEM_MLKEM768_P256',
    'KEM_MLKEM1024_P384',
  ],
  kdf: ['KDF_SHAKE128', 'KDF_SHAKE256', 'KDF_TurboSHAKE128', 'KDF_TurboSHAKE256'],
  aead: ['AEAD_ChaCha20Poly1305'],
}

export default {
  async test() {
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

    const vectorResults = await runVectorValidation({
      HPKE,
      vectors,
      vectorsPq,
      passingImplementations,
    })

    console.log(`Vector validation: ${vectorResults.passed}/${vectorResults.total} passed`)

    if (vectorResults.failed > 0) {
      throw new Error(`${vectorResults.failed} vector validation failure(s)`)
    }
  },
}
