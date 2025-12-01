import it, * as test from 'node:test'

import * as HPKE from '../index.ts'
import { KEMS, NOBLE_KEMS, AEADS } from './support.ts'

const empty = new Uint8Array()

const notUint8Array = [
  { name: 'null', value: null },
  { name: 'undefined', value: undefined },
  { name: 'string', value: 'not Uint8Array' },
  { name: 'number', value: 42 },
  { name: 'plain array', value: [1, 2, 3] },
  { name: 'ArrayBuffer', value: new ArrayBuffer(16) },
  { name: 'object', value: {} },
]

const notBoolean = [
  { name: 'null', value: null },
  { name: 'undefined', value: undefined },
  { name: 'string', value: 'not a boolean' },
  { name: 'number', value: 1 },
  { name: 'Uint8Array', value: new Uint8Array(32) },
  { name: 'plain array', value: [true] },
  { name: 'object', value: {} },
]

// Generate shared key pairs for all KEMs to avoid regenerating in every test
const keys = new Map<number, HPKE.KeyPair>()
async function getKeyPair(suite: HPKE.CipherSuite) {
  let kp = keys.get(suite.KEM.id)
  if (!kp) {
    kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    keys.set(suite.KEM.id, kp)
  }
  return kp
}

test.describe('Validations', () => {
  test.describe('CipherSuite constructor', () => {
    const notFactory = [
      { name: 'null', value: null },
      { name: 'undefined', value: undefined },
      { name: 'string', value: 'not a factory' },
      { name: 'number', value: 42 },
      { name: 'object', value: {} },
      { name: 'array', value: [] },
    ]

    for (const invalid of notFactory) {
      it(`rejects ${invalid.name} as KEM`, (t: test.TestContext) => {
        t.assert.throws(
          // @ts-expect-error
          () => new HPKE.CipherSuite(invalid.value, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM),
          TypeError,
        )
      })

      it(`rejects ${invalid.name} as KDF`, (t: test.TestContext) => {
        t.assert.throws(
          () =>
            new HPKE.CipherSuite(
              HPKE.KEM_DHKEM_P256_HKDF_SHA256,
              // @ts-expect-error
              invalid.value,
              HPKE.AEAD_AES_128_GCM,
            ),
          TypeError,
        )
      })

      it(`rejects ${invalid.name} as AEAD`, (t: test.TestContext) => {
        t.assert.throws(
          () =>
            new HPKE.CipherSuite(
              HPKE.KEM_DHKEM_P256_HKDF_SHA256,
              HPKE.KDF_HKDF_SHA256,
              // @ts-expect-error
              invalid.value,
            ),
          TypeError,
        )
      })
    }

    it('rejects factory that returns wrong type discriminator for KEM', (t: test.TestContext) => {
      const badKEM = () => ({ type: 'WRONG', id: 1, name: 'bad' })
      t.assert.throws(
        // @ts-expect-error
        () => new HPKE.CipherSuite(badKEM, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM),
        { name: 'TypeError', message: 'Invalid "KEM"' },
      )
    })

    it('rejects factory that returns wrong type discriminator for KDF', (t: test.TestContext) => {
      const badKDF = () => ({ type: 'WRONG', id: 1, name: 'bad' })
      t.assert.throws(
        // @ts-expect-error
        () => new HPKE.CipherSuite(HPKE.KEM_DHKEM_P256_HKDF_SHA256, badKDF, HPKE.AEAD_AES_128_GCM),
        { name: 'TypeError', message: 'Invalid "KDF"' },
      )
    })

    it('rejects factory that returns wrong type discriminator for AEAD', (t: test.TestContext) => {
      const badAEAD = () => ({ type: 'WRONG', id: 1, name: 'bad' })
      t.assert.throws(
        // @ts-expect-error
        () => new HPKE.CipherSuite(HPKE.KEM_DHKEM_P256_HKDF_SHA256, HPKE.KDF_HKDF_SHA256, badAEAD),
        { name: 'TypeError', message: 'Invalid "AEAD"' },
      )
    })

    it('rejects factory that throws for KEM', (t: test.TestContext) => {
      const throwingKEM = () => {
        throw new Error('KEM error')
      }
      t.assert.throws(
        () => new HPKE.CipherSuite(throwingKEM, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM),
        { name: 'TypeError', message: 'Invalid "KEM"' },
      )
    })

    it('rejects factory that throws for KDF', (t: test.TestContext) => {
      const throwingKDF = () => {
        throw new Error('KDF error')
      }
      t.assert.throws(
        () =>
          new HPKE.CipherSuite(HPKE.KEM_DHKEM_P256_HKDF_SHA256, throwingKDF, HPKE.AEAD_AES_128_GCM),
        { name: 'TypeError', message: 'Invalid "KDF"' },
      )
    })

    it('rejects factory that throws for AEAD', (t: test.TestContext) => {
      const throwingAEAD = () => {
        throw new Error('AEAD error')
      }
      t.assert.throws(
        () =>
          new HPKE.CipherSuite(HPKE.KEM_DHKEM_P256_HKDF_SHA256, HPKE.KDF_HKDF_SHA256, throwingAEAD),
        { name: 'TypeError', message: 'Invalid "AEAD"' },
      )
    })
  })

  for (const KEM of KEMS.values()) {
    if (!KEM.supported) continue
    const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    test.describe('Public key deserialization', () => {
      it(`${suite.KEM.name} rejects invalid public key length`, async (t: test.TestContext) => {
        const invalidKey = new Uint8Array(10) // Wrong length
        await t.assert.rejects(suite.DeserializePublicKey(invalidKey), { name: 'DeserializeError' })
      })
    })

    test.describe('Encapsulated secret deserialization', () => {
      it(`${suite.KEM.name} rejects invalid encapsulated secret length`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const invalidEnc = new Uint8Array(10) // Wrong length
        await t.assert.rejects(suite.Open(kp.privateKey, invalidEnc, empty), { name: 'DecapError' })
      })
    })
  }

  test.describe('AEAD decryption failure', () => {
    for (const AEAD of AEADS.values()) {
      // Skip export-only AEAD since it doesn't support Seal/Open
      if (!AEAD.supported) continue
      if (AEAD.factory === HPKE.AEAD_EXPORT_ONLY) continue

      // AEAD validation is independent of KEM/KDF, just test with one suite per AEAD
      const suite = new HPKE.CipherSuite(
        HPKE.KEM_DHKEM_P256_HKDF_SHA256,
        HPKE.KDF_HKDF_SHA256,
        AEAD.factory,
      )

      it(`${AEAD.name} throws OpenError on invalid ciphertext`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const pt = new Uint8Array(16)

        const { encapsulatedSecret: enc, ciphertext: ct } = await suite.Seal(kp.publicKey, pt)

        // Corrupt the ciphertext
        const corruptedCt = new Uint8Array(ct)
        if (corruptedCt[0] !== undefined) {
          corruptedCt[0] ^= 0xff
        }

        await t.assert.rejects(suite.Open(kp.privateKey, enc, corruptedCt), { name: 'OpenError' })
      })

      it(`${AEAD.name} throws OpenError on wrong AAD`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const aad = new Uint8Array(16).fill(0xaa)
        const pt = new Uint8Array(16)

        const { encapsulatedSecret: enc, ciphertext: ct } = await suite.Seal(kp.publicKey, pt, {
          aad,
        })

        // Use different AAD
        const wrongAad = new Uint8Array(16).fill(0xbb)

        await t.assert.rejects(suite.Open(kp.privateKey, enc, ct, { aad: wrongAad }), {
          name: 'OpenError',
        })
      })
    }
  })

  test.describe('Export-only AEAD validation', () => {
    const suite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_EXPORT_ONLY,
    )

    it('Single-shot Seal rejects Export-only AEAD', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const pt = new Uint8Array(16)
      await t.assert.rejects(suite.Seal(kp.publicKey, pt), {
        name: 'TypeError',
        message: 'Export-only AEAD cannot be used with Seal',
      })
    })

    it('Single-shot Open rejects Export-only AEAD', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const fakeEnc = new Uint8Array(suite.KEM.Nenc)
      const fakeCt = new Uint8Array(16)
      await t.assert.rejects(suite.Open(kp.privateKey, fakeEnc, fakeCt), {
        name: 'TypeError',
        message: 'Export-only AEAD cannot be used with Open',
      })
    })

    it('Context Seal rejects Export-only AEAD', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { ctx } = await suite.SetupSender(kp.publicKey)
      const pt = new Uint8Array(16)
      await t.assert.rejects(ctx.Seal(pt, empty), {
        name: 'TypeError',
        message: 'Export-only AEAD cannot be used with Seal',
      })
    })

    it('Context Open rejects Export-only AEAD', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
      const ctx = await suite.SetupRecipient(kp.privateKey, enc)
      const fakeCt = new Uint8Array(16)
      await t.assert.rejects(ctx.Open(fakeCt, empty), {
        name: 'TypeError',
        message: 'Export-only AEAD cannot be used with Open',
      })
    })
  })

  for (const KEM of KEMS.values()) {
    if (!KEM.supported) continue
    const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)

    test.describe('KEM DeriveKeyPair IKM length validation', () => {
      it(`${suite.KEM.name} rejects insufficient IKM length`, async (t: test.TestContext) => {
        const insufficientIkm = new Uint8Array(suite.KEM.Nsk - 1)

        await t.assert.rejects(suite.DeriveKeyPair(insufficientIkm), {
          name: 'DeriveKeyPairError',
          message: 'Insufficient "ikm" length',
        })
      })
    })

    test.describe('KEM DeserializePublicKey length validation', () => {
      it(`${suite.KEM.name} rejects invalid public key length`, async (t: test.TestContext) => {
        const invalidKey = new Uint8Array(suite.KEM.Npk - 1)

        await t.assert.rejects(suite.DeserializePublicKey(invalidKey), (err: Error) => {
          t.assert.strictEqual(err.name, 'DeserializeError')
          t.assert.ok(err.cause instanceof Error)
          t.assert.strictEqual(err.cause.message, 'Invalid "publicKey" length')
          return true
        })
      })
    })

    test.describe('KEM DeserializePrivateKey length validation', () => {
      it(`${suite.KEM.name} rejects invalid private key length`, async (t: test.TestContext) => {
        const invalidKey = new Uint8Array(suite.KEM.Nsk - 1)

        await t.assert.rejects(suite.DeserializePrivateKey(invalidKey), (err: Error) => {
          t.assert.strictEqual(err.name, 'DeserializeError')
          t.assert.ok(err.cause instanceof Error)
          t.assert.strictEqual(err.cause.message, 'Invalid "privateKey" length')
          return true
        })
      })
    })
  }

  for (const KEM of KEMS.values()) {
    if (!KEM.supported) continue
    const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
    test.describe('DHKEM DeserializePublicKey value validation', () => {
      if (
        suite.KEM.name.includes('DHKEM') &&
        (suite.KEM.name.includes('P-256') ||
          suite.KEM.name.includes('P-384') ||
          suite.KEM.name.includes('P-521'))
      ) {
        it(`${suite.KEM.name} rejects all-zero public key`, async (t: test.TestContext) => {
          const zeroKey = new Uint8Array(suite.KEM.Npk) // All zeros

          await t.assert.rejects(suite.DeserializePublicKey(zeroKey), {
            name: 'DeserializeError',
            message: 'Public key deserialization failed',
          })
        })
      }
    })
  }

  test.describe('KEM Encap key type validation', () => {
    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue
      it(`${KEM.name} Encap rejects private key`, async (t: test.TestContext) => {
        const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
        const kp = await getKeyPair(suite)
        // Try to use private key instead of public key
        await t.assert.rejects(suite.SendExport(kp.privateKey, empty, 32), {
          name: 'TypeError',
          message: 'Invalid "publicKey"',
        })
      })
    }
  })

  test.describe('KEM Decap key type validation', () => {
    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue
      it(`${KEM.name} Decap rejects public key`, async (t: test.TestContext) => {
        const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SendExport(kp.publicKey, empty, 32)
        // Try to use public key instead of private key
        await t.assert.rejects(suite.ReceiveExport(kp.publicKey, enc, empty, 32), {
          name: 'TypeError',
          message: 'Invalid "privateKey"',
        })
      })
    }
  })

  test.describe('KEM Encap algorithm validation', () => {
    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue
      it(`${KEM.name} Encap rejects key with wrong algorithm`, async (t: test.TestContext) => {
        const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
        // Get a key from a different KEM
        let differentKEM: typeof KEM | undefined
        for (const otherKEM of KEMS.values()) {
          if (otherKEM !== KEM) {
            differentKEM = otherKEM
            break
          }
        }
        if (!differentKEM) {
          t.skip('No other KEM available for testing')
          return
        }

        const wrongKp = await getKeyPair(
          new HPKE.CipherSuite(differentKEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY),
        )
        await t.assert.rejects(suite.SendExport(wrongKp.publicKey, empty, 32), (err: Error) => {
          t.assert.strictEqual(err.name, 'EncapError')
          t.assert.ok(err.cause instanceof Error)
          t.assert.match(err.cause.message, /key (algorithm|namedCurve) must be/)
          return true
        })
      })
    }
  })

  test.describe('KEM Decap algorithm validation', () => {
    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue
      it(`${KEM.name} Decap rejects key with wrong algorithm`, async (t: test.TestContext) => {
        const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
        // Get a key from a different KEM
        let differentKEM: typeof KEM | undefined
        for (const otherKEM of KEMS.values()) {
          if (otherKEM !== KEM) {
            differentKEM = otherKEM
            break
          }
        }
        if (!differentKEM) {
          t.skip('No other KEM available for testing')
          return
        }

        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SendExport(kp.publicKey, empty, 32)
        const wrongKp = await getKeyPair(
          new HPKE.CipherSuite(differentKEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY),
        )
        await t.assert.rejects(
          suite.ReceiveExport(wrongKp.privateKey, enc, empty, 32),
          (err: Error) => {
            t.assert.strictEqual(err.name, 'DecapError')
            t.assert.ok(err.cause instanceof Error)
            t.assert.match(err.cause.message, /key (algorithm|namedCurve) must be/)
            return true
          },
        )
      })
    }
  })

  test.describe('PSK validation', () => {
    const suite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_EXPORT_ONLY,
    )

    it('SetupSender rejects PSK shorter than 32 bytes', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const shortPsk = new Uint8Array(31) // One byte short
      const pskId = new Uint8Array(32)
      await t.assert.rejects(suite.SetupSender(kp.publicKey, { psk: shortPsk, pskId }), {
        message: 'Insufficient PSK length',
        name: 'TypeError',
      })
    })

    it('SetupRecipient rejects PSK shorter than 32 bytes', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
      const shortPsk = new Uint8Array(31) // One byte short
      const pskId = new Uint8Array(32)
      await t.assert.rejects(suite.SetupRecipient(kp.privateKey, enc, { psk: shortPsk, pskId }), {
        message: 'Insufficient PSK length',
        name: 'TypeError',
      })
    })

    const invalidCases = [
      { name: 'psk without pskId (undefined)', psk: new Uint8Array(32), pskId: undefined },
      { name: 'psk without pskId (empty)', psk: new Uint8Array(32), pskId: empty },
      { name: 'pskId without psk (undefined)', psk: undefined, pskId: new Uint8Array(32) },
      { name: 'pskId without psk (empty)', psk: empty, pskId: new Uint8Array(32) },
    ]

    const validCases = [
      { name: 'both psk and pskId', psk: new Uint8Array(32), pskId: new Uint8Array(32) },
      { name: 'neither psk nor pskId', psk: undefined, pskId: undefined },
      { name: 'empty psk and pskId', psk: empty, pskId: empty },
    ]

    for (const { name, psk, pskId } of invalidCases) {
      it(`SetupSender rejects ${name}`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        await t.assert.rejects(suite.SetupSender(kp.publicKey, { psk, pskId }), {
          message: 'Inconsistent PSK inputs',
          name: 'TypeError',
        })
      })

      it(`SetupRecipient rejects ${name}`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        await t.assert.rejects(suite.SetupRecipient(kp.privateKey, enc, { psk, pskId }), {
          message: 'Inconsistent PSK inputs',
          name: 'TypeError',
        })
      })
    }

    for (const { name, psk, pskId } of validCases) {
      it(`SetupSender accepts ${name}`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc, ctx } = await suite.SetupSender(kp.publicKey, {
          psk,
          pskId,
        })
        t.assert.ok(enc)
        t.assert.ok(ctx)
      })

      it(`SetupRecipient accepts ${name}`, async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey, { psk, pskId })
        const ctx = await suite.SetupRecipient(kp.privateKey, enc, { psk, pskId })
        t.assert.ok(ctx)
      })
    }

    // Test that empty PSK results in MODE_BASE (mode === 0x00), not MODE_PSK
    // This tests the fix for mode determination using psk?.byteLength instead of psk
    it('SetupSender with empty psk and pskId uses MODE_BASE', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { ctx } = await suite.SetupSender(kp.publicKey, { psk: empty, pskId: empty })
      t.assert.strictEqual(ctx.mode, HPKE.MODE_BASE)
    })

    it('SetupRecipient with empty psk and pskId uses MODE_BASE', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
      const ctx = await suite.SetupRecipient(kp.privateKey, enc, { psk: empty, pskId: empty })
      t.assert.strictEqual(ctx.mode, HPKE.MODE_BASE)
    })

    it('SetupSender with valid psk and pskId uses MODE_PSK', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const { ctx } = await suite.SetupSender(kp.publicKey, {
        psk: new Uint8Array(32),
        pskId: new Uint8Array(16),
      })
      t.assert.strictEqual(ctx.mode, HPKE.MODE_PSK)
    })

    it('SetupRecipient with valid psk and pskId uses MODE_PSK', async (t: test.TestContext) => {
      const kp = await getKeyPair(suite)
      const psk = new Uint8Array(32)
      const pskId = new Uint8Array(16)
      const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey, { psk, pskId })
      const ctx = await suite.SetupRecipient(kp.privateKey, enc, { psk, pskId })
      t.assert.strictEqual(ctx.mode, HPKE.MODE_PSK)
    })

    // Test that mode is consistent between sender and recipient when using empty PSK
    it('sender and recipient agree on MODE_BASE with empty psk/pskId', async (t: test.TestContext) => {
      const aeadSuite = new HPKE.CipherSuite(
        HPKE.KEM_DHKEM_P256_HKDF_SHA256,
        HPKE.KDF_HKDF_SHA256,
        HPKE.AEAD_AES_128_GCM,
      )
      const kp = await getKeyPair(aeadSuite)
      const plaintext = new Uint8Array([1, 2, 3, 4])

      // Encrypt with empty psk/pskId
      const { encapsulatedSecret: enc, ciphertext } = await aeadSuite.Seal(
        kp.publicKey,
        plaintext,
        { psk: empty, pskId: empty },
      )

      // Decrypt with empty psk/pskId - should succeed
      const decrypted = await aeadSuite.Open(kp.privateKey, enc, ciphertext, {
        psk: empty,
        pskId: empty,
      })
      t.assert.deepStrictEqual(decrypted, plaintext)

      // Decrypt without psk/pskId - should also succeed (same MODE_BASE)
      const decrypted2 = await aeadSuite.Open(kp.privateKey, enc, ciphertext)
      t.assert.deepStrictEqual(decrypted2, plaintext)
    })
  })

  test.describe('Uint8Array parameter validation', () => {
    const suite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_AES_128_GCM,
    )

    test.describe('Single-Shot Seal API', () => {
      it('rejects non-Uint8Array info', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          if (value === null || value === undefined) continue
          await t.assert.rejects(
            // @ts-expect-error
            suite.Seal(kp.publicKey, empty, { info: value }),
            { name: 'TypeError', message: '"info" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array aad', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null extractable is valid (defaults to empty)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Seal(kp.publicKey, empty, { aad: value }),
            { name: 'TypeError', message: '"aad" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pt', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.Seal(kp.publicKey, value),
            { name: 'TypeError', message: '"plaintext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array psk', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const pskId = new Uint8Array(32)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null psk is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Seal(kp.publicKey, empty, { psk: value, pskId }),
            { name: 'TypeError', message: '"psk" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pskId', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const psk = new Uint8Array(32)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null pskId is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Seal(kp.publicKey, empty, { psk, pskId: value }),
            { name: 'TypeError', message: '"pskId" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('Single-Shot Open API', () => {
      it('rejects non-Uint8Array encapsulatedSecret', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, value, empty),
            { name: 'TypeError', message: '"encapsulatedSecret" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array info', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.Seal(kp.publicKey, empty)
        for (const { name, value } of notUint8Array) {
          if (value === null || value === undefined) continue
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, enc, empty, { info: value }),
            { name: 'TypeError', message: '"info" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array aad', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc, ciphertext: ct } = await suite.Seal(kp.publicKey, empty)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null extractable is valid (defaults to empty)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, enc, ct, { aad: value }),
            { name: 'TypeError', message: '"aad" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array ct', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.Seal(kp.publicKey, empty)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, enc, value),
            { name: 'TypeError', message: '"ciphertext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array psk', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const pskId = new Uint8Array(32)
        const { encapsulatedSecret: enc, ciphertext: ct } = await suite.Seal(kp.publicKey, empty)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null psk is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, enc, ct, { psk: value, pskId }),
            { name: 'TypeError', message: '"psk" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pskId', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const psk = new Uint8Array(32)
        const { encapsulatedSecret: enc, ciphertext: ct } = await suite.Seal(kp.publicKey, empty)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null pskId is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.Open(kp.privateKey, enc, ct, { psk, pskId: value }),
            { name: 'TypeError', message: '"pskId" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('Context Seal API', () => {
      it('rejects non-Uint8Array aad', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { ctx } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null extractable is valid (defaults to empty)
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Seal(empty, value),
            { name: 'TypeError', message: '"aad" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pt', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { ctx } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Seal(value, empty),
            { name: 'TypeError', message: '"plaintext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('Context Open API', () => {
      it('rejects non-Uint8Array aad', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        const ctx = await suite.SetupRecipient(kp.privateKey, enc)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null extractable is valid (defaults to empty)
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Open(empty, value),
            { name: 'TypeError', message: '"aad" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array ct', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        const ctx = await suite.SetupRecipient(kp.privateKey, enc)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Open(value, empty),
            { name: 'TypeError', message: '"ciphertext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('SetupSender API', () => {
      it('rejects non-Uint8Array info', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          if (value === null || value === undefined) continue
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupSender(kp.publicKey, { info: value }),
            { name: 'TypeError', message: '"info" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array psk', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const pskId = new Uint8Array(32)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null psk is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupSender(kp.publicKey, { psk: value, pskId }),
            { name: 'TypeError', message: '"psk" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pskId', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const psk = new Uint8Array(32)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null pskId is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupSender(kp.publicKey, { psk, pskId: value }),
            { name: 'TypeError', message: '"pskId" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('SetupRecipient API', () => {
      it('rejects non-Uint8Array encapsulatedSecret', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupRecipient(kp.privateKey, value),
            { name: 'TypeError', message: '"encapsulatedSecret" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array info', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          if (value === null || value === undefined) continue
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupRecipient(kp.privateKey, enc, { info: value }),
            { name: 'TypeError', message: '"info" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array psk', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const pskId = new Uint8Array(32)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null psk is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupRecipient(kp.privateKey, enc, { psk: value, pskId }),
            { name: 'TypeError', message: '"psk" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array pskId', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const psk = new Uint8Array(32)
        const { encapsulatedSecret: enc } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          if (value == null) continue // undefined/null pskId is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.SetupRecipient(kp.privateKey, enc, { psk, pskId: value }),
            { name: 'TypeError', message: '"pskId" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('Context Export API', () => {
      it('rejects non-Uint8Array exporterContext', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { ctx } = await suite.SetupSender(kp.publicKey)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Export(value, 32),
            { name: 'TypeError', message: '"exporterContext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects invalid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { ctx } = await suite.SetupSender(kp.publicKey)
        const invalidLValues = [
          { name: 'null', value: null },
          { name: 'undefined', value: undefined },
          { name: 'string', value: 'not a number' },
          { name: 'Uint8Array', value: new Uint8Array(32) },
          { name: 'plain array', value: [32] },
          { name: 'object', value: {} },
          { name: 'NaN', value: NaN },
          { name: 'float', value: 32.5 },
          { name: 'negative', value: -1 },
          { name: 'zero', value: 0 },
          { name: 'too large', value: 0x10000 },
        ]
        for (const { name, value } of invalidLValues) {
          await t.assert.rejects(
            // @ts-expect-error
            ctx.Export(empty, value),
            { name: 'TypeError', message: '"L" must be a positive integer not exceeding 65535' },
            `Failed for ${name}`,
          )
        }
      })

      it('accepts valid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { ctx } = await suite.SetupSender(kp.publicKey)
        // Test boundary values - use KDF-specific limits
        // For HKDF-SHA256: 255 * 32 = 8160 max
        // For SHAKE/TurboSHAKE: higher limits, but 8160 is safe for all
        let exported = await ctx.Export(empty, 1) // minimum
        t.assert.strictEqual(exported.length, 1)

        exported = await ctx.Export(empty, 8160) // safe for all KDFs
        t.assert.strictEqual(exported.length, 8160)

        exported = await ctx.Export(empty, 32) // typical value
        t.assert.strictEqual(exported.length, 32)
      })
    })

    test.describe('Single-Shot SendExport API', () => {
      it('rejects non-Uint8Array exporterContext', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.SendExport(kp.publicKey, value, 32),
            { name: 'TypeError', message: '"exporterContext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects invalid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const invalidLValues = [
          { name: 'null', value: null },
          { name: 'undefined', value: undefined },
          { name: 'string', value: 'not a number' },
          { name: 'Uint8Array', value: new Uint8Array(32) },
          { name: 'plain array', value: [32] },
          { name: 'object', value: {} },
          { name: 'NaN', value: NaN },
          { name: 'float', value: 32.5 },
          { name: 'negative', value: -1 },
          { name: 'zero', value: 0 },
          { name: 'too large', value: 0x10000 },
        ]
        for (const { name, value } of invalidLValues) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.SendExport(kp.publicKey, empty, value),
            { name: 'TypeError', message: '"L" must be a positive integer not exceeding 65535' },
            `Failed for ${name}`,
          )
        }
      })

      it('accepts valid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        // Test boundary values - use KDF-specific limits
        // For HKDF-SHA256: 255 * 32 = 8160 max
        // For SHAKE/TurboSHAKE: higher limits, but 8160 is safe for all
        let result = await suite.SendExport(kp.publicKey, empty, 1) // minimum
        t.assert.strictEqual(result.exportedSecret.length, 1)

        result = await suite.SendExport(kp.publicKey, empty, 8160) // safe for all KDFs
        t.assert.strictEqual(result.exportedSecret.length, 8160)

        result = await suite.SendExport(kp.publicKey, empty, 32) // typical value
        t.assert.strictEqual(result.exportedSecret.length, 32)
      })
    })

    test.describe('Single-Shot ReceiveExport API', () => {
      it('rejects non-Uint8Array encapsulatedSecret', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.ReceiveExport(kp.privateKey, value, empty, 32),
            { name: 'TypeError', message: '"encapsulatedSecret" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-Uint8Array exporterContext', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SendExport(kp.publicKey, empty, 32)
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.ReceiveExport(kp.privateKey, enc, value, 32),
            { name: 'TypeError', message: '"exporterContext" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects invalid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        const { encapsulatedSecret: enc } = await suite.SendExport(kp.publicKey, empty, 32)
        const invalidLValues = [
          { name: 'null', value: null },
          { name: 'undefined', value: undefined },
          { name: 'string', value: 'not a number' },
          { name: 'Uint8Array', value: new Uint8Array(32) },
          { name: 'plain array', value: [32] },
          { name: 'object', value: {} },
          { name: 'NaN', value: NaN },
          { name: 'float', value: 32.5 },
          { name: 'negative', value: -1 },
          { name: 'zero', value: 0 },
          { name: 'too large', value: 0x10000 },
        ]
        for (const { name, value } of invalidLValues) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.ReceiveExport(kp.privateKey, enc, empty, value),
            { name: 'TypeError', message: '"L" must be a positive integer not exceeding 65535' },
            `Failed for ${name}`,
          )
        }
      })

      it('accepts valid L values', async (t: test.TestContext) => {
        const kp = await getKeyPair(suite)
        // Test boundary values - use KDF-specific limits
        // For HKDF-SHA256: 255 * 32 = 8160 max
        // For SHAKE/TurboSHAKE: higher limits, but 8160 is safe for all
        let enc = (await suite.SendExport(kp.publicKey, empty, 1)).encapsulatedSecret
        let exported = await suite.ReceiveExport(kp.privateKey, enc, empty, 1) // minimum
        t.assert.strictEqual(exported.length, 1)

        enc = (await suite.SendExport(kp.publicKey, empty, 8160)).encapsulatedSecret
        exported = await suite.ReceiveExport(kp.privateKey, enc, empty, 8160) // safe for all KDFs
        t.assert.strictEqual(exported.length, 8160)

        enc = (await suite.SendExport(kp.publicKey, empty, 32)).encapsulatedSecret
        exported = await suite.ReceiveExport(kp.privateKey, enc, empty, 32) // typical value
        t.assert.strictEqual(exported.length, 32)
      })
    })
  })

  test.describe('Key pair and serialization API validation', () => {
    const suite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_AES_128_GCM,
    )

    test.describe('GenerateKeyPair', () => {
      it('rejects non-boolean extractable', async (t: test.TestContext) => {
        for (const { name, value } of notBoolean) {
          if (value == null) continue // undefined/null extractable is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.GenerateKeyPair(value),
            { name: 'TypeError', message: '"extractable" must be boolean' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('DeriveKeyPair', () => {
      it('rejects non-Uint8Array ikm', async (t: test.TestContext) => {
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.DeriveKeyPair(value),
            { name: 'TypeError', message: '"ikm" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-boolean extractable', async (t: test.TestContext) => {
        const ikm = new Uint8Array(suite.KEM.Nsk)
        for (const { name, value } of notBoolean) {
          if (value == null) continue // undefined/null extractable is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.DeriveKeyPair(ikm, value),
            { name: 'TypeError', message: '"extractable" must be boolean' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('DeserializePrivateKey', () => {
      it('rejects non-Uint8Array key', async (t: test.TestContext) => {
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.DeserializePrivateKey(value),
            { name: 'TypeError', message: '"privateKey" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })

      it('rejects non-boolean extractable', async (t: test.TestContext) => {
        // Generate an extractable key pair so we can serialize it
        const kp = await suite.GenerateKeyPair(true)
        const serialized = await suite.SerializePrivateKey(kp.privateKey)
        for (const { name, value } of notBoolean) {
          if (value == null) continue // undefined/null extractable is valid (defaults to false)
          await t.assert.rejects(
            // @ts-expect-error
            suite.DeserializePrivateKey(serialized, value),
            { name: 'TypeError', message: '"extractable" must be boolean' },
            `Failed for ${name}`,
          )
        }
      })
    })

    test.describe('DeserializePublicKey', () => {
      it('rejects non-Uint8Array key', async (t: test.TestContext) => {
        for (const { name, value } of notUint8Array) {
          await t.assert.rejects(
            // @ts-expect-error
            suite.DeserializePublicKey(value),
            { name: 'TypeError', message: '"publicKey" must be Uint8Array' },
            `Failed for ${name}`,
          )
        }
      })
    })
  })
})

test.describe('Non-extractable key protection (built-in and noble KEMs)', () => {
  const kems: Array<
    [string, Map<number, { factory: HPKE.KEMFactory; name: string; supported: boolean }>]
  > = [
    ['built-in', KEMS],
    ['noble', NOBLE_KEMS],
  ]

  for (const [lib, KEMS] of kems) {
    for (const [id, { factory, supported, name }] of KEMS) {
      if (!supported) continue

      it(`${lib}: ${name} - prevents extraction of non-extractable private keys`, async (t: test.TestContext) => {
        // Create a simple suite with this KEM
        const suite = new HPKE.CipherSuite(factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

        // Generate a non-extractable key pair
        const kp = await suite.GenerateKeyPair(false)

        // Verify the key is marked as non-extractable
        t.assert.strictEqual(
          kp.privateKey.extractable,
          false,
          'Private key should be non-extractable',
        )

        // Attempt to serialize via CipherSuite API should fail
        await t.assert.rejects(
          suite.SerializePrivateKey(kp.privateKey),
          { name: 'TypeError', message: '"privateKey" must be extractable' },
          'CipherSuite.SerializePrivateKey should reject non-extractable keys',
        )

        // Also verify via direct KEM interface
        const kem = factory()
        await t.assert.rejects(
          kem.SerializePrivateKey(kp.privateKey),
          (err: Error) => {
            t.assert.ok(
              err.name === 'InvalidAccessException' ||
                err.name === 'InvalidAccessError' ||
                (err.name === 'TypeError' && err.message === 'key must be extractable'),
            )

            return true
          },
          'KEM.SerializePrivateKey should reject non-extractable keys',
        )
      })
    }
  }
})

test.describe('Uint8Array view with non-zero offset handling', () => {
  // These tests verify that Uint8Array views with non-zero byteOffset are handled correctly.
  // The internal ab() function properly slices the buffer when byteLength !== buffer.byteLength.

  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_P256_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_128_GCM,
  )

  it('correctly handles Uint8Array views with non-zero offset in Seal/Open', async (t: test.TestContext) => {
    const kp = await suite.GenerateKeyPair()

    // Create a larger buffer and use views into it
    const largeBuffer = new ArrayBuffer(128)
    const fullView = new Uint8Array(largeBuffer)

    // Fill with test pattern
    for (let i = 0; i < 128; i++) {
      fullView[i] = i
    }

    // Create plaintext as a view with non-zero offset
    const plaintextOffset = 32
    const plaintextLength = 16
    const plaintext = new Uint8Array(largeBuffer, plaintextOffset, plaintextLength)

    // Create AAD as a view with non-zero offset
    const aadOffset = 64
    const aadLength = 8
    const aad = new Uint8Array(largeBuffer, aadOffset, aadLength)

    // Encrypt using views
    const { encapsulatedSecret, ciphertext } = await suite.Seal(kp.publicKey, plaintext, { aad })

    // Decrypt and verify
    const decrypted = await suite.Open(kp, encapsulatedSecret, ciphertext, { aad })

    // Verify the decrypted content matches the original plaintext view
    t.assert.deepStrictEqual(decrypted, plaintext)

    // Also verify content is correct (bytes 32-47 from the pattern)
    const expected = new Uint8Array(plaintextLength)
    for (let i = 0; i < plaintextLength; i++) {
      expected[i] = plaintextOffset + i
    }
    t.assert.deepStrictEqual(decrypted, expected)
  })

  it('correctly handles Uint8Array views with non-zero offset in Export', async (t: test.TestContext) => {
    const kp = await suite.GenerateKeyPair()

    // Create exporter context as a view with non-zero offset
    const largeBuffer = new ArrayBuffer(64)
    const fullView = new Uint8Array(largeBuffer)
    for (let i = 0; i < 64; i++) {
      fullView[i] = i * 2
    }

    const contextOffset = 16
    const contextLength = 12
    const exporterContext = new Uint8Array(largeBuffer, contextOffset, contextLength)

    // Export using view
    const { encapsulatedSecret, exportedSecret } = await suite.SendExport(
      kp.publicKey,
      exporterContext,
      32,
    )

    // Receive export using the same context view
    const receivedSecret = await suite.ReceiveExport(kp, encapsulatedSecret, exporterContext, 32)

    // Both sides should derive the same secret
    t.assert.deepStrictEqual(exportedSecret, receivedSecret)
  })

  it('correctly handles info parameter as Uint8Array view with non-zero offset', async (t: test.TestContext) => {
    const kp = await suite.GenerateKeyPair()

    // Create info as a view with non-zero offset
    const largeBuffer = new ArrayBuffer(48)
    const fullView = new Uint8Array(largeBuffer)
    for (let i = 0; i < 48; i++) {
      fullView[i] = 255 - i
    }

    const infoOffset = 8
    const infoLength = 16
    const info = new Uint8Array(largeBuffer, infoOffset, infoLength)

    const plaintext = new Uint8Array([1, 2, 3, 4])

    // Encrypt with info view
    const { encapsulatedSecret, ciphertext } = await suite.Seal(kp.publicKey, plaintext, { info })

    // Decrypt with same info view
    const decrypted = await suite.Open(kp, encapsulatedSecret, ciphertext, { info })

    t.assert.deepStrictEqual(decrypted, plaintext)
  })
})
