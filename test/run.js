// Shared runtime-agnostic test logic for HPKE
// Used by both index.html (browser) and test/run-workerd.js (workerd)

// ============================================================================
// ALGORITHM ID MAPPINGS
// ============================================================================

export const ALGORITHM_IDS = {
  // KEMs
  KEM_DHKEM_P256_HKDF_SHA256: 0x0010,
  KEM_DHKEM_P384_HKDF_SHA384: 0x0011,
  KEM_DHKEM_P521_HKDF_SHA512: 0x0012,
  KEM_DHKEM_X25519_HKDF_SHA256: 0x0020,
  KEM_DHKEM_X448_HKDF_SHA512: 0x0021,
  KEM_ML_KEM_512: 0x0040,
  KEM_ML_KEM_768: 0x0041,
  KEM_ML_KEM_1024: 0x0042,
  KEM_MLKEM768_P256: 0x0050,
  KEM_MLKEM1024_P384: 0x0051,
  KEM_MLKEM768_X25519: 0x647a,

  // KDFs
  KDF_HKDF_SHA256: 0x0001,
  KDF_HKDF_SHA384: 0x0002,
  KDF_HKDF_SHA512: 0x0003,
  KDF_SHAKE128: 0x0010,
  KDF_SHAKE256: 0x0011,
  KDF_TurboSHAKE128: 0x0012,
  KDF_TurboSHAKE256: 0x0013,

  // AEADs
  AEAD_AES_128_GCM: 0x0001,
  AEAD_AES_256_GCM: 0x0002,
  AEAD_ChaCha20Poly1305: 0x0003,
  AEAD_EXPORT_ONLY: 0xffff,
}

// ============================================================================
// ALGORITHM DISCOVERY
// ============================================================================

/** Extracts algorithms from a library object by prefix */
export const extractAlgorithms = (library, prefix, label, isNoble = false) =>
  Object.keys(library)
    .filter((key) => key.startsWith(prefix))
    .map((name) => ({ name, displayName: `[${label}] ${name}`, factory: library[name], isNoble }))
    .sort((a, b) => a.name.localeCompare(b.name))

// ============================================================================
// HELPERS
// ============================================================================

/** Gets the component object from a test based on the test's component type */
export const getTestComponent = (test) => test[test.testingComponent]

/** Helper to verify two Uint8Arrays match */
const assertUint8ArraysEqual = (actual, expected, errorPrefix) => {
  if (actual.length !== expected.length) throw new Error(`${errorPrefix}: length mismatch`)
  if (!actual.every((val, i) => val === expected[i]))
    throw new Error(`${errorPrefix}: content mismatch`)
}

// ============================================================================
// TEST FUNCTIONS
// ============================================================================

/** Performs encryption/decryption test for regular AEAD modes */
async function testRegularAEAD(HPKE, suite, recipientKeyPair) {
  const plaintext = new TextEncoder().encode('Hello, HPKE!')

  // Sender seals using recipient's public key
  const { encapsulatedSecret, ciphertext } = await suite.Seal(recipientKeyPair.publicKey, plaintext)

  // Recipient opens using their private key
  const decrypted = await suite.Open(recipientKeyPair, encapsulatedSecret, ciphertext)

  // Verify decrypted matches plaintext
  const decryptedText = new TextDecoder().decode(decrypted)
  if (decryptedText !== 'Hello, HPKE!') {
    throw new Error(`Decryption mismatch: expected "Hello, HPKE!", got "${decryptedText}"`)
  }
}

/** Performs export-only mode test */
async function testExportOnlyMode(HPKE, suite, recipientKeyPair) {
  const exporterContext = new TextEncoder().encode('test context')
  const L = 32

  // Sender exports secret using recipient's public key
  const { encapsulatedSecret, exportedSecret } = await suite.SendExport(
    recipientKeyPair.publicKey,
    exporterContext,
    L,
  )

  // Recipient receives exported secret using their private key
  const receivedSecret = await suite.ReceiveExport(
    recipientKeyPair,
    encapsulatedSecret,
    exporterContext,
    L,
  )

  // Verify the secrets match
  assertUint8ArraysEqual(exportedSecret, receivedSecret, 'Exported secret mismatch')
}

// ============================================================================
// ALGORITHM TEST RUNNER
// ============================================================================

/**
 * Runs the HPKE algorithm compatibility tests.
 *
 * @param {object} options
 * @param {object} options.HPKE - The HPKE library namespace
 * @param {object} options.Noble - The Noble extensibility library namespace
 * @param {{ kem: string[]; kdf: string[]; aead: string[] }} options.unsupported - Algorithms
 *   expected to fail natively
 * @param {{ onlyNative?: boolean; onlyNoble?: boolean }} [options.mode] - Test mode
 * @param {function} [options.onTestComplete] - Called after each test with (test, tests)
 * @param {boolean} [options.yieldToEventLoop] - If true, yields to the event loop between tests for
 *   UI updates
 *
 * @returns {Promise<object>} { results, tests, passingImplementations, ALL_KEMS, ALL_KDFS,
 *   ALL_AEADS }
 */
export async function runAlgorithmTests({
  HPKE,
  Noble,
  unsupported,
  mode = {},
  onTestComplete,
  yieldToEventLoop,
}) {
  const onlyNative = mode.onlyNative || false
  const onlyNoble = mode.onlyNoble || false
  const both = (onlyNative && onlyNoble) || (!onlyNative && !onlyNoble)

  // Extract algorithms from both libraries
  const KEMS = extractAlgorithms(HPKE, 'KEM_', 'native')
  const KDFS = extractAlgorithms(HPKE, 'KDF_', 'native')
  const AEADS = extractAlgorithms(HPKE, 'AEAD_', 'native').filter(
    (x) => x.name !== 'AEAD_EXPORT_ONLY',
  )

  const NOBLE_KEMS = extractAlgorithms(Noble, 'KEM_', 'extensibility', true)
  const NOBLE_KDFS = extractAlgorithms(Noble, 'KDF_', 'extensibility', true)
  const NOBLE_AEADS = extractAlgorithms(Noble, 'AEAD_', 'extensibility', true)

  const ALL_KEMS = both ? KEMS.concat(NOBLE_KEMS) : onlyNative ? KEMS : NOBLE_KEMS
  const ALL_KDFS = both ? KDFS.concat(NOBLE_KDFS) : onlyNative ? KDFS : NOBLE_KDFS
  const ALL_AEADS = both ? AEADS.concat(NOBLE_AEADS) : onlyNative ? AEADS : NOBLE_AEADS

  // Baselines — well-supported algorithms paired with the component under test
  const baselineKEM = KEMS.find((k) => k.name === 'KEM_DHKEM_P256_HKDF_SHA256')
  const baselineKDF = KDFS.find((k) => k.name === 'KDF_HKDF_SHA256')
  const baselineAEAD = AEADS.find((a) => a.name === 'AEAD_AES_128_GCM')

  /** Determines if a test is expected to fail based on runtime support */
  const isExpectedToFail = (test) => {
    const component = test[test.testingComponent]
    // Noble implementations provide fallbacks and always pass
    if (component.isNoble) return false
    return unsupported[test.testingComponent].includes(component.name)
  }

  // Track passing implementations by algorithm ID
  const passingImplementations = { kem: new Map(), kdf: new Map(), aead: new Map() }

  // ============================================================================
  // TEST GENERATION
  // ============================================================================

  const generateTests = () => {
    const testList = []
    const testConfigs = [
      {
        algorithms: ALL_KEMS,
        component: 'kem',
        baselines: { kdf: baselineKDF, aead: baselineAEAD },
      },
      {
        algorithms: ALL_KDFS,
        component: 'kdf',
        baselines: { kem: baselineKEM, aead: baselineAEAD },
      },
      {
        algorithms: ALL_AEADS,
        component: 'aead',
        baselines: { kem: baselineKEM, kdf: baselineKDF },
      },
    ]

    testConfigs.forEach(({ algorithms, component, baselines }) => {
      algorithms.forEach((algorithm) => {
        const test = {
          id: testList.length,
          ...baselines,
          [component]: algorithm,
          testingComponent: component,
          status: 'pending',
          error: null,
          expectedToFail: false,
        }
        test.expectedToFail = isExpectedToFail(test)
        testList.push(test)
      })
    })
    return testList
  }

  // ============================================================================
  // TEST EXECUTION
  // ============================================================================

  async function runTest(test) {
    test.status = 'running'

    try {
      const suite = new HPKE.CipherSuite(test.kem.factory, test.kdf.factory, test.aead.factory)

      // Generate test key pair
      await suite.GenerateKeyPair()
      const ikm = crypto.getRandomValues(new Uint8Array(suite.KEM.Nsk))
      const keyPair = await suite.DeriveKeyPair(ikm, true)

      // Serialize and deserialize keys to test that functionality
      const serializedPublicKey = await suite.SerializePublicKey(keyPair.publicKey)
      const serializedPrivateKey = await suite.SerializePrivateKey(keyPair.privateKey)
      const recipientPrivateKey = await suite.DeserializePrivateKey(serializedPrivateKey, true)
      const recipientPublicKey = await suite.DeserializePublicKey(serializedPublicKey)
      const recipientKeyPair = { publicKey: recipientPublicKey, privateKey: recipientPrivateKey }

      // Test based on AEAD mode
      if (test.aead.name === 'AEAD_EXPORT_ONLY') {
        await testExportOnlyMode(HPKE, suite, recipientKeyPair)
      } else {
        await testRegularAEAD(HPKE, suite, recipientKeyPair)
      }

      test.status = 'passed'
      test.error = null

      // Collect passing implementation
      const component = test.testingComponent
      const componentAlgo = test[component]
      const algoId = ALGORITHM_IDS[componentAlgo.name]

      if (algoId !== undefined) {
        if (!passingImplementations[component].has(algoId)) {
          passingImplementations[component].set(algoId, [])
        }
        passingImplementations[component]
          .get(algoId)
          .push({ factory: componentAlgo.factory, isNoble: componentAlgo.isNoble })
      }
    } catch (error) {
      test.status = 'failed'
      test.error = error.message || String(error)
    }

    if (onTestComplete) {
      onTestComplete(test, tests)
    }
  }

  // ============================================================================
  // RUN ALL TESTS
  // ============================================================================

  const tests = generateTests()

  // Prioritize baseline algorithms
  const priorityTests = tests.filter((t) => {
    const component = getTestComponent(t)
    return (
      (t.testingComponent === 'kem' && component.name === 'KEM_DHKEM_P256_HKDF_SHA256') ||
      (t.testingComponent === 'kdf' && component.name === 'KDF_HKDF_SHA256') ||
      (t.testingComponent === 'aead' && component.name === 'AEAD_AES_128_GCM')
    )
  })
  const otherTests = tests.filter((t) => !priorityTests.includes(t))

  for (const test of priorityTests) {
    await runTest(test)
    if (yieldToEventLoop) await new Promise((resolve) => setTimeout(resolve, 10))
  }
  for (const test of otherTests) {
    await runTest(test)
    if (yieldToEventLoop) await new Promise((resolve) => setTimeout(resolve, 10))
  }

  // ============================================================================
  // RESULTS
  // ============================================================================

  const results = {
    total: tests.length,
    passed: tests.filter((t) => t.status === 'passed').length,
    failed: tests.filter((t) => t.status === 'failed').length,
    expectedFailures: tests.filter((t) => t.status === 'failed' && t.expectedToFail).length,
    unexpectedFailures: tests.filter((t) => t.status === 'failed' && !t.expectedToFail).length,
    unexpectedPasses: tests.filter((t) => t.status === 'passed' && t.expectedToFail).length,
    tests: tests.map((t) => {
      const component = getTestComponent(t)
      return {
        id: t.id,
        component: t.testingComponent,
        name: component.displayName || component.name,
        suite: {
          kem: t.kem.displayName || t.kem.name,
          kdf: t.kdf.displayName || t.kdf.name,
          aead: t.aead.displayName || t.aead.name,
        },
        status: t.status,
        expectedToFail: t.expectedToFail,
        error: t.error,
      }
    }),
  }

  return { results, tests, passingImplementations, ALL_KEMS, ALL_KDFS, ALL_AEADS }
}

// ============================================================================
// VECTOR VALIDATION
// ============================================================================

/**
 * Runs vector validation tests against passing implementations.
 *
 * @param {object} options
 * @param {object} options.HPKE - The HPKE library namespace
 * @param {Array} options.vectors - Test vectors array
 * @param {Array} options.vectorsPq - Post-quantum test vectors array
 * @param {object} options.passingImplementations - Passing implementations from runAlgorithmTests
 * @param {function} [options.onProgress] - Called with { completedOps, passedOps, failedOps,
 *   totalOps }
 * @param {boolean} [options.yieldToEventLoop] - If true, yields to the event loop periodically for
 *   UI updates
 *
 * @returns {Promise<{ total: number; passed: number; failed: number }>}
 */
export async function runVectorValidation({
  HPKE,
  vectors,
  vectorsPq,
  passingImplementations,
  onProgress,
  yieldToEventLoop,
}) {
  const allVectors = [...vectors, ...vectorsPq].filter((v) => {
    if (v.mode !== 0x00 && v.mode !== 0x01) return false
    return true
  })

  let completedOps = 0
  let passedOps = 0
  let failedOps = 0
  let totalOps = 0

  // Calculate total operations
  for (const vector of allVectors) {
    const kemImpls = passingImplementations.kem.get(vector.kem_id) || []
    const kdfImpls = passingImplementations.kdf.get(vector.kdf_id) || []
    const aeadImpls = passingImplementations.aead.get(vector.aead_id) || []

    if (!kemImpls.length || !kdfImpls.length || !aeadImpls.length) continue

    const combinations = kemImpls.length * kdfImpls.length * aeadImpls.length
    totalOps += combinations * ((vector.encryptions?.length || 0) + (vector.exports?.length || 0))
  }

  if (totalOps === 0) {
    return { total: 0, passed: 0, failed: 0 }
  }

  const recipientKeyPairCache = new Map()

  for (const vector of allVectors) {
    const kemImpls = passingImplementations.kem.get(vector.kem_id) || []
    const kdfImpls = passingImplementations.kdf.get(vector.kdf_id) || []
    const aeadImpls = passingImplementations.aead.get(vector.aead_id) || []

    if (!kemImpls.length || !kdfImpls.length || !aeadImpls.length) continue

    for (const kemImpl of kemImpls) {
      for (const kdfImpl of kdfImpls) {
        for (const aeadImpl of aeadImpls) {
          const suite = new HPKE.CipherSuite(kemImpl.factory, kdfImpl.factory, aeadImpl.factory)
          const ikmR = Uint8Array.fromHex(vector.ikmR)

          // Check cache for this kemImpl and ikmR combination
          if (!recipientKeyPairCache.has(kemImpl)) {
            recipientKeyPairCache.set(kemImpl, new Map())
          }
          const kemCache = recipientKeyPairCache.get(kemImpl)

          let recipientKeyPair
          if (kemCache.has(vector.ikmR)) {
            recipientKeyPair = kemCache.get(vector.ikmR)
          } else {
            recipientKeyPair = await suite.DeriveKeyPair(ikmR, true)
            kemCache.set(vector.ikmR, recipientKeyPair)
          }
          const enc = Uint8Array.fromHex(vector.enc)

          const options = {
            info: Uint8Array.fromHex(vector.info),
            psk: vector.psk ? Uint8Array.fromHex(vector.psk) : undefined,
            pskId: vector.psk_id ? Uint8Array.fromHex(vector.psk_id) : undefined,
          }

          const ctx = await suite.SetupRecipient(recipientKeyPair, enc, options)

          // Test all encryptions
          if (vector.encryptions) {
            for (const encryption of vector.encryptions) {
              try {
                const ciphertext = Uint8Array.fromHex(encryption.ct)
                const aad = Uint8Array.fromHex(encryption.aad)
                const expectedPlaintext = Uint8Array.fromHex(encryption.pt)
                const decrypted = await ctx.Open(ciphertext, aad)
                assertUint8ArraysEqual(decrypted, expectedPlaintext, 'Plaintext mismatch')
                passedOps++
              } catch (e) {
                failedOps++
              } finally {
                completedOps++
                if (onProgress) {
                  onProgress({ completedOps, passedOps, failedOps, totalOps })
                }
              }
            }
          }

          // Test all exports
          if (vector.exports) {
            for (const exportTest of vector.exports) {
              try {
                const exporterContext = Uint8Array.fromHex(exportTest.exporter_context)
                const L = exportTest.L
                const expectedExportedValue = Uint8Array.fromHex(exportTest.exported_value)
                const exportedValue = await ctx.Export(exporterContext, L)
                assertUint8ArraysEqual(exportedValue, expectedExportedValue, 'Export mismatch')
                passedOps++
              } catch (e) {
                failedOps++
              } finally {
                completedOps++
                if (onProgress) {
                  onProgress({ completedOps, passedOps, failedOps, totalOps })
                }
              }
            }
          }

          if (yieldToEventLoop) await new Promise((resolve) => setTimeout(resolve, 0))
        }
      }
    }
  }

  return { total: totalOps, passed: passedOps, failed: failedOps }
}
