import it, * as test from 'node:test'
import * as fs from 'node:fs/promises'

import {
  findReadmeSupportMismatches,
  formatReadmeSupportMismatch,
  runAlgorithmTests,
} from './run.js'
import * as HPKE from '../index.ts'

type Runtime = 'node' | 'deno' | 'bun' | 'electron'

const runtime = (() => {
  // @ts-expect-error
  if (typeof Deno === 'object') return 'deno'
  // @ts-expect-error
  if (typeof Bun === 'object') return 'bun'
  if (process.versions.electron) return 'electron'
  return 'node'
})() as Runtime

test.describe('README support matrix', () => {
  const readme = `
### Key Encapsulation Mechanisms (KEM)

| Algorithm | Native support | [Extensibility][] |
| :--- | :--- | :---: |
| DHKEM(P-256, HKDF-SHA256) <sub>\`0x0010\`</sub> | All tested runtimes | ✓ |
| DHKEM(P-384, HKDF-SHA384) <sub>\`0x0011\`</sub> | Chromium | ✓ |
| DHKEM(P-521, HKDF-SHA512) <sub>\`0x0012\`</sub> | Firefox | ✓ |
| DHKEM(X25519, HKDF-SHA256) <sub>\`0x0020\`</sub> | WebKit | ✓ |
| DHKEM(X448, HKDF-SHA512) <sub>\`0x0021\`</sub> | Chromium, Firefox | ✓ |
| ML-KEM-768 <sub>\`0x0041\`</sub> | Node.js, Cloudflare Workers[^cf-modern], Electron, Chromium Preview | ✓ |
`
  const results = {
    tests: [
      'KEM_DHKEM_P256_HKDF_SHA256',
      'KEM_DHKEM_P384_HKDF_SHA384',
      'KEM_DHKEM_P521_HKDF_SHA512',
      'KEM_DHKEM_X25519_HKDF_SHA256',
      'KEM_DHKEM_X448_HKDF_SHA512',
      'KEM_ML_KEM_768',
    ].map((algorithm) => ({ status: 'passed', component: 'kem' as const, algorithm })),
  }

  for (const [runtime, runtimeName, unsupported] of [
    [
      'chromium',
      'Chromium',
      ['KEM_DHKEM_P521_HKDF_SHA512', 'KEM_DHKEM_X25519_HKDF_SHA256', 'KEM_ML_KEM_768'],
    ],
    [
      'firefox',
      'Firefox',
      ['KEM_DHKEM_P384_HKDF_SHA384', 'KEM_DHKEM_X25519_HKDF_SHA256', 'KEM_ML_KEM_768'],
    ],
    [
      'webkit',
      'WebKit',
      [
        'KEM_DHKEM_P384_HKDF_SHA384',
        'KEM_DHKEM_P521_HKDF_SHA512',
        'KEM_DHKEM_X448_HKDF_SHA512',
        'KEM_ML_KEM_768',
      ],
    ],
    [
      'electron',
      'Electron',
      [
        'KEM_DHKEM_P384_HKDF_SHA384',
        'KEM_DHKEM_P521_HKDF_SHA512',
        'KEM_DHKEM_X25519_HKDF_SHA256',
        'KEM_DHKEM_X448_HKDF_SHA512',
      ],
    ],
    [
      'workerd',
      'Cloudflare Workers',
      [
        'KEM_DHKEM_P384_HKDF_SHA384',
        'KEM_DHKEM_P521_HKDF_SHA512',
        'KEM_DHKEM_X25519_HKDF_SHA256',
        'KEM_DHKEM_X448_HKDF_SHA512',
      ],
    ],
  ] as const) {
    it(`matches ${runtimeName} in the Native support column`, (t: test.TestContext) => {
      const mismatches = findReadmeSupportMismatches({ results, readme, runtime })

      t.assert.deepStrictEqual(
        mismatches.map(({ algorithm }) => algorithm),
        unsupported,
      )
      for (const mismatch of mismatches) {
        t.assert.ok(
          formatReadmeSupportMismatch(mismatch).endsWith(`does not mark ${runtimeName} support`),
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

it('only substitutes generated keys for unsupported native PQ key derivation', async (t: test.TestContext) => {
  const failDerivation = (error: Error) => () => ({
    ...HPKE.KEM_DHKEM_P256_HKDF_SHA256(),
    async DeriveKeyPair(): Promise<never> {
      throw error
    },
  })
  const unsupported = failDerivation(new HPKE.NotSupportedError())
  const { results } = await runAlgorithmTests({
    HPKE: {
      CipherSuite: HPKE.CipherSuite,
      NotSupportedError: HPKE.NotSupportedError,
      KEM_DHKEM_P256_HKDF_SHA256: HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      KEM_DHKEM_P384_HKDF_SHA384: unsupported,
      KEM_ML_KEM_768: unsupported,
      KEM_MLKEM768_X25519: unsupported,
      KEM_ML_KEM_1024: failDerivation(new Error('derivation failed')),
      KDF_HKDF_SHA256: HPKE.KDF_HKDF_SHA256,
      AEAD_AES_128_GCM: HPKE.AEAD_AES_128_GCM,
    },
    Noble: { KEM_ML_KEM_512: unsupported },
    unsupported: { kem: [], kdf: [], aead: [] },
  })
  t.assert.deepStrictEqual(
    results.tests
      .filter((entry) => entry.status === 'failed')
      .map((entry) => entry.algorithm)
      .sort(),
    ['KEM_DHKEM_P384_HKDF_SHA384', 'KEM_ML_KEM_1024', 'KEM_ML_KEM_512'],
  )
})
