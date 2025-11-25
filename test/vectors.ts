import it, * as test from 'node:test'
import * as fs from 'node:fs/promises'
import * as assert from 'node:assert/strict'

import * as HPKE from '../index.ts'
import { label, KEMS, KDFS, AEADS, IDs, waitFor, hex } from './support.ts'

declare global {
  interface Uint8ArrayConstructor {
    fromBase64(
      base64String: string,
      options?: {
        alphabet?: 'base64' | 'base64url'
        lastChunkHandling?: 'loose' | 'strict' | 'stop-before-partial'
      },
    ): Uint8Array
    fromHex(hexString: string): Uint8Array
  }

  interface Uint8Array {
    toBase64(options?: { alphabet?: 'base64' | 'base64url'; omitPadding?: boolean }): string
    toHex(): string
    setFromBase64(
      base64String: string,
      options?: {
        alphabet?: 'base64' | 'base64url'
        lastChunkHandling?: 'loose' | 'strict' | 'stop-before-partial'
      },
    ): { read: number; written: number }
    setFromHex(hexString: string): { read: number; written: number }
  }
}

function toHexString(num: number, padding = 4) {
  return '0x' + num.toString(16).toUpperCase().padStart(padding, '0')
}

function highlightMissing(str?: string) {
  return str !== undefined ? `?${str}` : undefined
}

const getSuiteName = (prefix: string, id: number) =>
  highlightMissing(
    Object.entries(IDs).find(([name, idValue]) => name.startsWith(prefix) && idValue === id)?.[0],
  ) ?? `?${prefix}<${toHexString(id)}>`

interface Vector {
  mode: number
  kem_id: number
  kdf_id: number
  aead_id: number
  info: string
  psk?: string
  psk_id?: string
  ikmR: string
  ikmS: string
  skRm: string
  pkRm: string
  enc: string
  shared_secret: string
  suite_id: string
  key: string
  base_nonce: string
  exporter_secret: string
  encryptions: Array<{ aad: string; ct: string; nonce: string; pt: string }>
  exports: Array<{ exporter_context: string; L: number; exported_value: string }>
}

const vectors: Vector[] = [
  ...JSON.parse(await fs.readFile('./test/vectors.json', 'ascii')),
  ...JSON.parse(await fs.readFile('./test/vectors-pq.json', 'ascii')),
]

let total = 0
for (const vector of vectors) {
  const i = total
  total++
  // Skip Auth modes (0x02 and 0x03)
  if (vector.mode === 0x02 || vector.mode === 0x03) {
    continue
  }
  const KDF = KDFS.get(vector.kdf_id)
  const KEM = KEMS.get(vector.kem_id)
  const AEAD = AEADS.get(vector.aead_id)

  let skR!: HPKE.Key
  let pkR!: HPKE.Key
  let kpR!: HPKE.KeyPair

  const keys = () => {
    assert.ok(skR)
    assert.ok(pkR)
    assert.ok(kpR)
  }

  // Test KEM's key management only
  if (KEM?.supported === true) {
    const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
    test.describe(`[${i}] ${KEM.name}`, () => {
      it('DeriveKeyPair', async (t: test.TestContext) => {
        const ikmR = hex(vector.ikmR)
        // @ts-expect-error
        const extractable = typeof crypto.subtle.getPublicKey !== 'function'
        await t.assert.doesNotReject(
          Promise.all([
            suite.DeriveKeyPair(ikmR, extractable).then(({ privateKey, publicKey }) => {
              skR = privateKey
              pkR = publicKey
            }),
            suite.DeriveKeyPair(ikmR).then(({ privateKey, publicKey }) => {
              kpR = { publicKey, privateKey }
            }),
          ]),
        )
      })

      it('GenerateKeyPair', async (t: test.TestContext) => {
        await t.assert.doesNotReject(suite.GenerateKeyPair())
      })

      it('SerializePublicKey', async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const pkRm = await suite.SerializePublicKey(pkR)
        t.assert.deepStrictEqual(pkRm, hex(vector.pkRm))
      })

      it('DeserializePublicKey', async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const pkRm = hex(vector.pkRm)
        const deserializedKey = await suite.DeserializePublicKey(pkRm)
        t.assert.deepStrictEqual(deserializedKey.algorithm, pkR.algorithm)
        t.assert.notEqual(deserializedKey, pkR)
        t.assert.deepStrictEqual(await suite.SerializePublicKey(deserializedKey), pkRm)
      })

      it('SerializePrivateKey', async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const skR = await suite.DeserializePrivateKey(hex(vector.skRm), true)
        const skRm = await suite.SerializePrivateKey(skR)
        t.assert.deepStrictEqual(skRm, hex(vector.skRm))
      })

      it('DeserializePrivateKey', async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const skRm = hex(vector.skRm)
        const deserializedKey = await suite.DeserializePrivateKey(skRm, true)
        t.assert.notEqual(deserializedKey, skRm)
        t.assert.deepStrictEqual(deserializedKey.algorithm, skR.algorithm)
        t.assert.deepStrictEqual(await suite.SerializePrivateKey(deserializedKey), skRm)
      })
    })
  }

  if (!KEM || !KDF || !AEAD) {
    const suite = {
      KEM: KEM ?? { id: vector.kem_id, name: getSuiteName('KEM', vector.kem_id) },
      KDF: KDF ?? { id: vector.kdf_id, name: getSuiteName('KDF', vector.kdf_id) },
      AEAD: AEAD ?? { id: vector.aead_id, name: getSuiteName('AEAD', vector.aead_id) },
    }
    it.skip(`[${i}][not implemented] ${label(suite as HPKE.CipherSuite, vector.mode)}`)
    continue
  }

  const suite = new HPKE.CipherSuite(KEM.factory, KDF.factory, AEAD.factory)

  if (!KEM.supported || !KDF.supported || !AEAD.supported) {
    it.skip(`[${i}][not supported] ${label(suite, vector.mode)}`)
    continue
  }

  test.describe(`[${i}] ${label(suite, vector.mode)}`, () => {
    // Helper to prepare common test data
    const getTestData = () => ({
      enc: hex(vector.enc),
      info: hex(vector.info),
      psk: vector.psk ? hex(vector.psk) : undefined,
      pskId: vector.psk_id ? hex(vector.psk_id) : undefined,
    })

    // Helper for testing Open operation with different key types
    const testOpen = (keyType: 'privateKey' | 'keyPair') => async (t: test.TestContext) => {
      await waitFor(keys, { interval: 0 })
      const encryptions0 = vector.encryptions[0]!
      const { enc, info, psk, pskId } = getTestData()
      const aad = hex(encryptions0.aad)
      const ct = hex(encryptions0.ct)
      const pt = hex(encryptions0.pt)
      const key = keyType === 'privateKey' ? skR : kpR
      t.assert.deepStrictEqual(await suite.Open(key, enc, ct, { aad, info, psk, pskId }), pt)
    }

    // Helper for testing ReceiveExport operation with different key types
    const testReceiveExport =
      (keyType: 'privateKey' | 'keyPair') => async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const exports0 = vector.exports[0]!
        const { enc, info, psk, pskId } = getTestData()
        const exporter_context = hex(exports0.exporter_context)
        const exported_value = hex(exports0.exported_value)
        const L = exports0.L
        const key = keyType === 'privateKey' ? skR : kpR
        t.assert.deepStrictEqual(
          await suite.ReceiveExport(key, enc, exporter_context, L, { info, psk, pskId }),
          exported_value,
        )
      }

    // Helper for testing SetupRecipient with Open & Export
    const testSetupRecipient =
      (keyType: 'privateKey' | 'keyPair') => async (t: test.TestContext) => {
        await waitFor(keys, { interval: 0 })
        const { enc, info, psk, pskId } = getTestData()
        const key = keyType === 'privateKey' ? skR : kpR

        const ctx = await suite.SetupRecipient(key, enc, { info, psk, pskId })

        // Test all encryptions in sequence
        for (const encryption of vector.encryptions) {
          const aad = hex(encryption.aad)
          const ct = hex(encryption.ct)
          const pt = hex(encryption.pt)
          t.assert.deepStrictEqual(await ctx.Open(ct, aad), pt)
        }

        // Test all exports
        for (const exportData of vector.exports) {
          const exporter_context = hex(exportData.exporter_context)
          const exported_value = hex(exportData.exported_value)
          const L = exportData.L
          t.assert.deepStrictEqual(await ctx.Export(exporter_context, L), exported_value)
        }
      }

    if (vector.aead_id !== 0xffff) {
      it('Open', testOpen('privateKey'))
      it('Open (with KeyPair)', testOpen('keyPair'))
    }

    it('ReceiveExport', testReceiveExport('privateKey'))
    it('ReceiveExport (with KeyPair)', testReceiveExport('keyPair'))

    it('SetupR > Open & Export', testSetupRecipient('privateKey'))
    it('SetupR > Open & Export (with KeyPair)', testSetupRecipient('keyPair'))
  })
}
