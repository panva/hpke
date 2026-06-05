import it, * as test from 'node:test'
import * as fs from 'node:fs/promises'

import {
  findReadmeSupportMismatches,
  formatReadmeSupportMismatch,
  runAlgorithmTests,
} from './run.js'
import * as HPKE from '../index.ts'

type Runtime = 'node' | 'deno' | 'bun'

const runtime = (() => {
  // @ts-expect-error
  if (typeof Deno === 'object') return 'deno'
  // @ts-expect-error
  if (typeof Bun === 'object') return 'bun'
  return 'node'
})() as Runtime

test.describe('README support matrix', () => {
  it(`${runtime} native support is reflected in README.md`, async (t: test.TestContext) => {
    const readme = await fs.readFile('./README.md', 'utf8')
    const { results } = await runAlgorithmTests({
      HPKE,
      Noble: {},
      unsupported: { kem: [], kdf: [], aead: [] },
      mode: { onlyNative: true },
    })
    const mismatches = findReadmeSupportMismatches({ results, readme, runtime })

    t.assert.deepStrictEqual(mismatches.map(formatReadmeSupportMismatch), [])
  })
})
