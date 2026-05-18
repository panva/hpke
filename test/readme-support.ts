import it, * as test from 'node:test'
import * as fs from 'node:fs/promises'

import { findReadmeSupportMismatches, formatReadmeSupportMismatch } from './run.js'
import { AEADS, KDFS, KEMS } from './support.ts'

type Runtime = 'node' | 'deno' | 'bun'
type Component = 'kem' | 'kdf' | 'aead'
type AlgorithmEntry = { supported: boolean; name: string; impl: 'webcrypto' | 'noble' }

const runtime = (() => {
  // @ts-expect-error
  if (typeof Deno === 'object') return 'deno'
  // @ts-expect-error
  if (typeof Bun === 'object') return 'bun'
  return 'node'
})() as Runtime

function getNativePassingTests(component: Component, algorithms: Map<number, AlgorithmEntry>) {
  return [...algorithms.values()]
    .filter((algorithm) => algorithm.impl === 'webcrypto' && algorithm.supported)
    .filter((algorithm) => algorithm.name !== 'AEAD_EXPORT_ONLY')
    .map((algorithm) => ({
      status: 'passed',
      implementation: 'native',
      component,
      algorithm: algorithm.name,
    }))
}

test.describe('README support matrix', () => {
  it(`${runtime} native support is reflected in README.md`, async (t: test.TestContext) => {
    const readme = await fs.readFile('./README.md', 'utf8')
    const results = {
      tests: [
        ...getNativePassingTests('kem', KEMS),
        ...getNativePassingTests('kdf', KDFS),
        ...getNativePassingTests('aead', AEADS),
      ],
    }
    const mismatches = findReadmeSupportMismatches({ results, readme, runtime })

    t.assert.deepStrictEqual(mismatches.map(formatReadmeSupportMismatch), [])
  })
})
