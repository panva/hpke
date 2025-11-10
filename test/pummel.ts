import it, * as test from 'node:test'

import * as HPKE from '../index.ts'
import {
  label,
  KEMS,
  KDFS,
  AEADS,
  UNSUPPORTED_KEMS,
  UNSUPPORTED_KDFS,
  UNSUPPORTED_AEADS,
} from './support.ts'

const empty = new Uint8Array()

// Helper to verify Uint8Array has exact underlying buffer
function assertExactBuffer(t: test.TestContext, arr: Uint8Array, name: string) {
  t.assert.strictEqual(
    arr.buffer.byteLength,
    arr.byteLength,
    `${name}: buffer.byteLength (${arr.buffer.byteLength}) !== byteLength (${arr.byteLength})`,
  )
}

// Helper to verify all Uint8Arrays in an object have exact underlying buffers
function assertAllExactBuffers(t: test.TestContext, obj: any, prefix = '') {
  if (obj instanceof Uint8Array) {
    assertExactBuffer(t, obj, prefix || 'Uint8Array')
  } else if (obj && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      const name = prefix ? `${prefix}.${key}` : key
      assertAllExactBuffers(t, value, name)
    }
  }
}

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

test.describe('pummel', () => {
  test.describe('Algorithm implementation returns', () => {
    for (const Algorithm of [...KEMS.values(), ...KDFS.values(), ...AEADS.values()]) {
      it(`${Algorithm.name}() returns are unique objects`, (t: test.TestContext) => {
        const a = Algorithm.factory()
        const b = Algorithm.factory()
        t.assert.notEqual(a, b)
        // @ts-expect-error
        a.id = 'foo'
        t.assert.notEqual(b.id, a.id)
      })
    }
  })

  async function testUnsupportedAlgorithm(
    t: test.TestContext,
    kemFactory: HPKE.KEMFactory,
    kdfFactory: HPKE.KDFFactory,
    aeadFactory: HPKE.AEADFactory,
    expectedAlgorithmName: string,
  ) {
    await t.assert.rejects(
      async () => {
        const suite = new HPKE.CipherSuite(kemFactory, kdfFactory, aeadFactory)
        const kp = await getKeyPair(suite)
        const pkR = kp.publicKey
        const skR = kp.privateKey
        const aad = empty
        const pt = new Uint8Array(12)
        const { encapsulated_key: enc, ciphertext: ct } = await suite.Seal(pkR, pt, aad)
        await suite.Open(skR, enc, ct, aad)
      },
      (err: Error) => {
        try {
          t.assert.strictEqual(err.name, 'NotSupportedError')
          t.assert.strictEqual(
            err.message,
            `${expectedAlgorithmName} is unsupported in this runtime`,
          )
        } catch (assertion) {
          // @ts-ignore Deno doesn't always conform to throwing DOMException with name=NotSupportedError on unsupported algorithms
          if (typeof Deno === 'object') {
            if (err.name === 'DeriveKeyPairError') return true
          }

          throw assertion
        }

        return true
      },
    )
  }

  for (const KEM of UNSUPPORTED_KEMS) {
    it(`[not supported] ${KEM.name}`, async (t: test.TestContext) => {
      await testUnsupportedAlgorithm(
        t,
        KEM.factory,
        HPKE.KDF_HKDF_SHA256,
        HPKE.AEAD_AES_128_GCM,
        KEM.factory().name,
      )
    })
  }

  for (const KDF of UNSUPPORTED_KDFS) {
    it(`[not supported] ${KDF.name}`, async (t: test.TestContext) => {
      await testUnsupportedAlgorithm(
        t,
        HPKE.KEM_DHKEM_P256_HKDF_SHA256,
        KDF.factory,
        HPKE.AEAD_AES_128_GCM,
        KDF.factory().name,
      )
    })
  }

  for (const AEAD of UNSUPPORTED_AEADS) {
    it(`[not supported] ${AEAD.name}`, async (t: test.TestContext) => {
      await testUnsupportedAlgorithm(
        t,
        HPKE.KEM_DHKEM_P256_HKDF_SHA256,
        HPKE.KDF_HKDF_SHA256,
        AEAD.factory,
        AEAD.factory().name,
      )
    })
  }

  test.describe('Key serialization round-trip tests', () => {
    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue

      const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)

      it(`${KEM.name}: DeriveKeyPair → Serialize → Deserialize → Serialize`, async (t: test.TestContext) => {
        const ikm = crypto.getRandomValues(new Uint8Array(suite.KEM.Nsk))
        const extractable = true

        // Generate a key pair
        const generatedKp = await suite.DeriveKeyPair(ikm, extractable)

        // Serialize both keys
        const serializedPub1 = await suite.SerializePublicKey(generatedKp.publicKey)
        const serializedPriv1 = await suite.SerializePrivateKey(generatedKp.privateKey)
        assertExactBuffer(t, serializedPub1, 'serializedPub1')
        assertExactBuffer(t, serializedPriv1, 'serializedPriv1')

        // Deserialize both keys
        const deserializedPub = await suite.DeserializePublicKey(serializedPub1)
        const deserializedPriv = await suite.DeserializePrivateKey(serializedPriv1, extractable)

        // Serialize again and verify they match
        const serializedPub2 = await suite.SerializePublicKey(deserializedPub)
        const serializedPriv2 = await suite.SerializePrivateKey(deserializedPriv)
        assertExactBuffer(t, serializedPub2, 'serializedPub2')
        assertExactBuffer(t, serializedPriv2, 'serializedPriv2')

        t.assert.deepStrictEqual(serializedPub2, serializedPub1, 'Public key round-trip failed')
        t.assert.deepStrictEqual(serializedPriv2, serializedPriv1, 'Private key round-trip failed')
      })

      it(`${KEM.name}: GenerateKeyPair → Serialize → Deserialize → Serialize`, async (t: test.TestContext) => {
        const extractable = true

        // Generate a key pair
        const generatedKp = await suite.GenerateKeyPair(extractable)

        // Serialize both keys
        const serializedPub1 = await suite.SerializePublicKey(generatedKp.publicKey)
        const serializedPriv1 = await suite.SerializePrivateKey(generatedKp.privateKey)
        assertExactBuffer(t, serializedPub1, 'serializedPub1')
        assertExactBuffer(t, serializedPriv1, 'serializedPriv1')

        // Deserialize both keys
        const deserializedPub = await suite.DeserializePublicKey(serializedPub1)
        const deserializedPriv = await suite.DeserializePrivateKey(serializedPriv1, extractable)

        // Serialize again and verify they match
        const serializedPub2 = await suite.SerializePublicKey(deserializedPub)
        const serializedPriv2 = await suite.SerializePrivateKey(deserializedPriv)
        assertExactBuffer(t, serializedPub2, 'serializedPub2')
        assertExactBuffer(t, serializedPriv2, 'serializedPriv2')

        t.assert.deepStrictEqual(serializedPub2, serializedPub1, 'Public key round-trip failed')
        t.assert.deepStrictEqual(serializedPriv2, serializedPriv1, 'Private key round-trip failed')
      })
    }
  })

  for (const AEAD of AEADS.values()) {
    for (const KEM of KEMS.values()) {
      for (const KDF of KDFS.values()) {
        const suite = new HPKE.CipherSuite(KEM.factory, KDF.factory, AEAD.factory)
        if (!KEM.supported || !KDF.supported || !AEAD.supported) {
          continue
        }
        for (const psk of [undefined, new Uint8Array(32)]) {
          const psk_id = psk ? new Uint8Array(32) : undefined
          const mode = !psk ? 0x00 : 0x01
          test.describe(label(suite, mode), () => {
            it('Roundtrip SendExport<>ReceiveExport', async (t: test.TestContext) => {
              const kpR = await getKeyPair(suite)
              const pkR = kpR.publicKey
              const skR = kpR.privateKey

              const info = empty
              const L = suite.AEAD.Nk || suite.KDF.Nh
              const exporter_context = empty

              const { encapsulated_key: enc, exported_secret: exported } = await suite.SendExport(
                pkR,
                exporter_context,
                L,
                {
                  info,
                  psk,
                  psk_id,
                },
              )
              assertExactBuffer(t, enc, 'SendExport.encapsulated_key')
              assertExactBuffer(t, exported, 'SendExport.exported_secret')
              const received = await suite.ReceiveExport(skR, enc, exporter_context, L, {
                info,
                psk,
                psk_id,
              })
              assertExactBuffer(t, received, 'ReceiveExport result')
              t.assert.deepStrictEqual(received, exported)
            })

            // Skip Seal/Open tests for export-only AEAD
            if (suite.AEAD.id === 0xffff) return

            it('Roundtrip Seal<>Open', async (t: test.TestContext) => {
              const kp = await getKeyPair(suite)
              const pkR = kp.publicKey
              const skR = kp.privateKey
              const info = empty
              const aad = empty
              const pt = new Uint8Array(12)
              const { encapsulated_key: enc, ciphertext: ct } = await suite.Seal(pkR, pt, aad, {
                info,
                psk,
                psk_id,
              })
              assertExactBuffer(t, enc, 'Seal.encapsulated_key')
              assertExactBuffer(t, ct, 'Seal.ciphertext')

              const opened = await suite.Open(skR, enc, ct, aad, { info, psk, psk_id })
              assertExactBuffer(t, opened, 'Open result')
              t.assert.deepStrictEqual(opened, pt)
            })

            it('Roundtrip Setup > Seal<>Open (3 messages)', async (t: test.TestContext) => {
              const kp = await getKeyPair(suite)
              const pkR = kp.publicKey
              const skR = kp.privateKey
              const info = empty

              const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR, {
                info,
                psk,
                psk_id,
              })
              assertExactBuffer(t, enc, 'SetupSender.encapsulated_key')
              t.assert.equal(contextS.Nt, suite.AEAD.Nt)
              const contextR = await suite.SetupRecipient(skR, enc, { info, psk, psk_id })

              t.assert.equal(contextS.mode, mode)
              t.assert.equal(contextR.mode, mode)

              t.assert.equal(contextS.mode, mode === 0x00 ? HPKE.MODE_BASE : HPKE.MODE_PSK)
              t.assert.equal(contextR.mode, mode === 0x00 ? HPKE.MODE_BASE : HPKE.MODE_PSK)

              // Message 1
              const aad1 = new Uint8Array([10, 20])
              const pt1 = new Uint8Array([1, 2, 3, 4])
              const ct1 = await contextS.Seal(pt1, aad1)
              assertExactBuffer(t, ct1, 'context.Seal ct1')
              const decrypted1 = await contextR.Open(ct1, aad1)
              assertExactBuffer(t, decrypted1, 'context.Open decrypted1')
              t.assert.deepStrictEqual(decrypted1, pt1)

              // Message 2
              const aad2 = new Uint8Array([30, 40, 50])
              const pt2 = new Uint8Array([5, 6, 7, 8, 9, 10])
              const ct2 = await contextS.Seal(pt2, aad2)
              assertExactBuffer(t, ct2, 'context.Seal ct2')
              const decrypted2 = await contextR.Open(ct2, aad2)
              assertExactBuffer(t, decrypted2, 'context.Open decrypted2')
              t.assert.deepStrictEqual(decrypted2, pt2)

              // Message 3
              const aad3 = new Uint8Array([60, 70, 80, 90])
              const pt3 = new Uint8Array([11, 12, 13])
              const ct3 = await contextS.Seal(pt3, aad3)
              assertExactBuffer(t, ct3, 'context.Seal ct3')
              const decrypted3 = await contextR.Open(ct3, aad3)
              assertExactBuffer(t, decrypted3, 'context.Open decrypted3')
              t.assert.deepStrictEqual(decrypted3, pt3)
            })
          })
        }
      }
    }
  }

  test.describe('Input mutation tests', () => {
    // Helper function to create a copy and check it hasn't been mutated
    function assertNotMutated(
      t: test.TestContext,
      original: Uint8Array,
      copy: Uint8Array,
      name: string,
    ) {
      t.assert.deepStrictEqual(original, copy, `${name} was mutated`)
    }

    for (const KEM of KEMS.values()) {
      if (!KEM.supported) continue
      if (KEM.name !== 'KEM_ML_KEM_768') continue

      it(`Public API does not mutate inputs with ${KEM.name}`, async (t: test.TestContext) => {
        const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

        // Test DeriveKeyPair
        const ikm = new Uint8Array(suite.KEM.Nsk).fill(42)
        const ikmCopy = ikm.slice()
        const kp = await suite.DeriveKeyPair(ikm, true)
        assertNotMutated(t, ikm, ikmCopy, 'ikm in DeriveKeyPair')

        const pkR = kp.publicKey
        const skR = kp.privateKey

        // Test SerializePublicKey
        const serializedPub = await suite.SerializePublicKey(pkR)

        // Test SerializePrivateKey (extractable key)
        const extractableKp = await suite.DeriveKeyPair(
          new Uint8Array(suite.KEM.Nsk).fill(99),
          true,
        )
        const serializedPriv = await suite.SerializePrivateKey(extractableKp.privateKey)

        // Test DeserializePublicKey
        const serializedPubCopy = serializedPub.slice()
        const _deserializedPub = await suite.DeserializePublicKey(serializedPub)
        assertNotMutated(
          t,
          serializedPub,
          serializedPubCopy,
          'serialized public key in DeserializePublicKey',
        )

        // Test DeserializePrivateKey
        const serializedPrivCopy = serializedPriv.slice()
        const _deserializedPriv = await suite.DeserializePrivateKey(serializedPriv, true)
        assertNotMutated(
          t,
          serializedPriv,
          serializedPrivCopy,
          'serialized private key in DeserializePrivateKey',
        )

        // Test Seal (single-shot)
        const info = new Uint8Array([1, 2, 3, 4, 5])
        const infoCopy = info.slice()
        const aad = new Uint8Array([10, 20, 30])
        const aadCopy = aad.slice()
        const pt = new Uint8Array([100, 101, 102, 103])
        const ptCopy = pt.slice()
        const psk = new Uint8Array(32).fill(55)
        const pskCopy = psk.slice()
        const psk_id = new Uint8Array(32).fill(66)
        const psk_idCopy = psk_id.slice()

        const { encapsulated_key: enc, ciphertext: ct } = await suite.Seal(pkR, pt, aad, {
          info,
          psk,
          psk_id,
        })
        assertExactBuffer(t, enc, 'mutation test - Seal.encapsulated_key')
        assertExactBuffer(t, ct, 'mutation test - Seal.ciphertext')
        assertNotMutated(t, info, infoCopy, 'info in Seal')
        assertNotMutated(t, aad, aadCopy, 'aad in Seal')
        assertNotMutated(t, pt, ptCopy, 'pt in Seal')
        assertNotMutated(t, psk, pskCopy, 'psk in Seal')
        assertNotMutated(t, psk_id, psk_idCopy, 'psk_id in Seal')

        // Test Open (single-shot)
        const encCopy = enc.slice()
        const ctCopy = ct.slice()
        const info2Copy = info.slice()
        const aad2Copy = aad.slice()
        const psk2Copy = psk.slice()
        const psk_id2Copy = psk_id.slice()

        const _decrypted = await suite.Open(skR, enc, ct, aad, { info, psk, psk_id })
        assertExactBuffer(t, _decrypted, 'mutation test - Open result')
        assertNotMutated(t, enc, encCopy, 'enc in Open')
        assertNotMutated(t, info, info2Copy, 'info in Open')
        assertNotMutated(t, aad, aad2Copy, 'aad in Open')
        assertNotMutated(t, ct, ctCopy, 'ct in Open')
        assertNotMutated(t, psk, psk2Copy, 'psk in Open')
        assertNotMutated(t, psk_id, psk_id2Copy, 'psk_id in Open')

        // Test SendExport
        const exportInfo = new Uint8Array([7, 8, 9])
        const exportInfoCopy = exportInfo.slice()
        const exporterContext = new Uint8Array([11, 12, 13])
        const exporterContextCopy = exporterContext.slice()
        const psk3Copy = psk.slice()
        const psk_id3Copy = psk_id.slice()

        const { encapsulated_key: enc2, exported_secret: _exported } = await suite.SendExport(
          pkR,
          exporterContext,
          32,
          { info: exportInfo, psk, psk_id },
        )
        assertExactBuffer(t, enc2, 'mutation test - SendExport.encapsulated_key')
        assertExactBuffer(t, _exported, 'mutation test - SendExport.exported_secret')
        assertNotMutated(t, exportInfo, exportInfoCopy, 'info in SendExport')
        assertNotMutated(t, exporterContext, exporterContextCopy, 'exporter_context in SendExport')
        assertNotMutated(t, psk, psk3Copy, 'psk in SendExport')
        assertNotMutated(t, psk_id, psk_id3Copy, 'psk_id in SendExport')

        // Test ReceiveExport
        const enc2Copy = enc2.slice()
        const exportInfo2Copy = exportInfo.slice()
        const exporterContext2Copy = exporterContext.slice()
        const psk4Copy = psk.slice()
        const psk_id4Copy = psk_id.slice()

        const _exported2 = await suite.ReceiveExport(skR, enc2, exporterContext, 32, {
          info: exportInfo,
          psk,
          psk_id,
        })
        assertExactBuffer(t, _exported2, 'mutation test - ReceiveExport result')
        assertNotMutated(t, enc2, enc2Copy, 'enc in ReceiveExport')
        assertNotMutated(t, exportInfo, exportInfo2Copy, 'info in ReceiveExport')
        assertNotMutated(
          t,
          exporterContext,
          exporterContext2Copy,
          'exporter_context in ReceiveExport',
        )
        assertNotMutated(t, psk, psk4Copy, 'psk in ReceiveExport')
        assertNotMutated(t, psk_id, psk_id4Copy, 'psk_id in ReceiveExport')

        // Test SetupSender
        const setupInfo = new Uint8Array([20, 21, 22])
        const setupInfoCopy = setupInfo.slice()
        const psk5Copy = psk.slice()
        const psk_id5Copy = psk_id.slice()

        const { encapsulated_key: enc3, ctx: senderCtx } = await suite.SetupSender(pkR, {
          info: setupInfo,
          psk,
          psk_id,
        })
        assertExactBuffer(t, enc3, 'mutation test - SetupSender.encapsulated_key')
        assertNotMutated(t, setupInfo, setupInfoCopy, 'info in SetupSender')
        assertNotMutated(t, psk, psk5Copy, 'psk in SetupSender')
        assertNotMutated(t, psk_id, psk_id5Copy, 'psk_id in SetupSender')

        // Test SetupRecipient
        const enc3Copy = enc3.slice()
        const setupInfo2Copy = setupInfo.slice()
        const psk6Copy = psk.slice()
        const psk_id6Copy = psk_id.slice()

        const recipientCtx = await suite.SetupRecipient(skR, enc3, { info: setupInfo, psk, psk_id })
        assertNotMutated(t, enc3, enc3Copy, 'enc in SetupRecipient')
        assertNotMutated(t, setupInfo, setupInfo2Copy, 'info in SetupRecipient')
        assertNotMutated(t, psk, psk6Copy, 'psk in SetupRecipient')
        assertNotMutated(t, psk_id, psk_id6Copy, 'psk_id in SetupRecipient')

        // Test SenderContext.Seal
        const ctxAad = new Uint8Array([30, 31, 32])
        const ctxAadCopy = ctxAad.slice()
        const ctxPt = new Uint8Array([40, 41, 42, 43])
        const ctxPtCopy = ctxPt.slice()

        const ctxCt = await senderCtx.Seal(ctxPt, ctxAad)
        assertExactBuffer(t, ctxCt, 'mutation test - SenderContext.Seal result')
        assertNotMutated(t, ctxAad, ctxAadCopy, 'aad in SenderContext.Seal')
        assertNotMutated(t, ctxPt, ctxPtCopy, 'pt in SenderContext.Seal')

        // Test RecipientContext.Open
        const ctxAad2Copy = ctxAad.slice()
        const ctxCtCopy = ctxCt.slice()

        const _ctxDecrypted = await recipientCtx.Open(ctxCt, ctxAad)
        assertExactBuffer(t, _ctxDecrypted, 'mutation test - RecipientContext.Open result')
        assertNotMutated(t, ctxAad, ctxAad2Copy, 'aad in RecipientContext.Open')
        assertNotMutated(t, ctxCt, ctxCtCopy, 'ct in RecipientContext.Open')

        // Test SenderContext.Export
        const senderExportCtx = new Uint8Array([50, 51, 52])
        const senderExportCtxCopy = senderExportCtx.slice()

        const _senderExported = await senderCtx.Export(senderExportCtx, 32)
        assertExactBuffer(t, _senderExported, 'mutation test - SenderContext.Export result')
        assertNotMutated(
          t,
          senderExportCtx,
          senderExportCtxCopy,
          'exporter_context in SenderContext.Export',
        )

        // Test RecipientContext.Export
        const recipientExportCtx = new Uint8Array([50, 51, 52])
        const recipientExportCtxCopy = recipientExportCtx.slice()

        const _recipientExported = await recipientCtx.Export(recipientExportCtx, 32)
        assertExactBuffer(t, _recipientExported, 'mutation test - RecipientContext.Export result')
        assertNotMutated(
          t,
          recipientExportCtx,
          recipientExportCtxCopy,
          'exporter_context in RecipientContext.Export',
        )
      })
    }
  })
})
