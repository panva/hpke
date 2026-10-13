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
  const browserReadme = `
### Key Encapsulation Mechanisms (KEM)

| Name | [Browsers][] |
| :--- | :----------: |
| DHKEM(P-256, HKDF-SHA256) <sub>\`0x0010\`</sub> | ✓ |
| DHKEM(P-384, HKDF-SHA384) <sub>\`0x0011\`</sub> | ◐[^chromium] |
| DHKEM(P-521, HKDF-SHA512) <sub>\`0x0012\`</sub> | ◐[^firefox] |
| DHKEM(X25519, HKDF-SHA256) <sub>\`0x0020\`</sub> | ◐[^webkit] |
| DHKEM(X448, HKDF-SHA512) <sub>\`0x0021\`</sub> | ◐[^chromium][^firefox] |
| ML-KEM-512 <sub>\`0x0040\`</sub> | |

[^chromium]: Chromium
[^firefox]: Firefox
[^webkit]: WebKit
`
  const browserResults = {
    tests: [
      'KEM_DHKEM_P256_HKDF_SHA256',
      'KEM_DHKEM_P384_HKDF_SHA384',
      'KEM_DHKEM_P521_HKDF_SHA512',
      'KEM_DHKEM_X25519_HKDF_SHA256',
      'KEM_DHKEM_X448_HKDF_SHA512',
      'KEM_ML_KEM_512',
    ].map((algorithm) => ({ status: 'passed', component: 'kem' as const, algorithm })),
  }

  for (const [runtime, browser, unsupported] of [
    [
      'chromium',
      'Chromium',
      ['KEM_DHKEM_P521_HKDF_SHA512', 'KEM_DHKEM_X25519_HKDF_SHA256', 'KEM_ML_KEM_512'],
    ],
    [
      'firefox',
      'Firefox',
      ['KEM_DHKEM_P384_HKDF_SHA384', 'KEM_DHKEM_X25519_HKDF_SHA256', 'KEM_ML_KEM_512'],
    ],
    [
      'webkit',
      'WebKit',
      [
        'KEM_DHKEM_P384_HKDF_SHA384',
        'KEM_DHKEM_P521_HKDF_SHA512',
        'KEM_DHKEM_X448_HKDF_SHA512',
        'KEM_ML_KEM_512',
      ],
    ],
  ] as const) {
    it(`checks ${browser} support independently in the Browsers column`, (t: test.TestContext) => {
      const mismatches = findReadmeSupportMismatches({
        results: browserResults,
        readme: browserReadme,
        runtime,
      })

      t.assert.deepStrictEqual(
        mismatches.map(({ algorithm }) => algorithm),
        unsupported,
      )
      for (const mismatch of mismatches) {
        t.assert.ok(
          formatReadmeSupportMismatch(mismatch).endsWith(`does not mark ${browser} support`),
        )
      }
    })
  }

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
