import it, * as test from 'node:test'
import { setImmediate } from 'node:timers/promises'

import * as HPKE from '../index.ts'
import { KEMS, KDFS, AEADS, NOBLE_KEMS, NOBLE_KDFS, NOBLE_AEADS, hex } from './support.ts'

type AlgorithmEntry<T> = { supported: boolean; factory: T; name: string }

type Implementation = {
  name: string
  KEMS: Map<number, AlgorithmEntry<HPKE.KEMFactory>>
  KDFS: Map<number, AlgorithmEntry<HPKE.KDFFactory>>
  AEADS: Map<number, AlgorithmEntry<HPKE.AEADFactory>>
}

type SpecialVector = {
  name: string
  mode: number
  kem_id: number
  kdf_id: number
  aead_id: number
  info: string
  ikmR: string
  skRm: string
  pkRm: string
  enc: string
  psk?: string
  psk_id?: string
  encryptions: Array<{ aad: string; ct: string; pt: string }>
  exports: Array<{ exporter_context: string; L: number; exported_value: string }>
}

const P256_ORDER = hex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')

const P256_REJECTION = {
  section: 'D.1 KEM Key Derivation with Rejection Sampling',
  rejectedCandidate: 'ffffffffc6e92ab863d8293933c849d280fc9a40f07471a06702bdf2eac30fa2',
  vector: {
    name: 'D.1 KEM Key Derivation with Rejection Sampling recipient context',
    mode: 0x00,
    kem_id: 0x0010,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    info: '4f6465206f6e2061204772656369616e2055726e',
    ikmR: '68706b652d656467652d703235362d72656a656374696f6e00000001c6be4ce7',
    skRm: 'd9cbff7adaa1c604a2e4fcfb762c9e1c5ed7d2e33b15fcad4c6c3f23a9637325',
    pkRm: '04d3bec6a691f47bbedd5caa1d51c7228f6afeeec5576495b855bbe6595e49643570be005fc177b3d80f6eeef280b1cf8a565d7ca28116dee2e875550ef3050ca8',
    enc: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
    encryptions: [
      {
        aad: '436f756e742d30',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: 'bcf25d5db84780b5b222eb26a63d8fb489c6a0bf1f6281cbc10c633707dbcda9af7cee7a57abdb59ce4c9d4162',
      },
    ],
    exports: [
      {
        exporter_context: '54657374436f6e74657874',
        L: 32,
        exported_value: 'abd921fc81dae75036e9146d2e5826e3ea075b410c1c46a0a0533a9e3e685490',
      },
    ],
  },
} satisfies { section: string; rejectedCandidate: string; vector: SpecialVector }

const SPECIAL_VECTORS: SpecialVector[] = [
  P256_REJECTION.vector,
  {
    name: 'D.2 Empty and Zero-Byte AEAD Inputs',
    mode: 0x00,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    info: '4f6465206f6e2061204772656369616e2055726e',
    ikmR: '6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037',
    skRm: '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
    pkRm: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    enc: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    encryptions: [
      { aad: '436f756e742d30', pt: '', ct: '3f431133aa05608a56675bec51d03e0f' },
      {
        aad: '',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8aa7d2bb71109b5730bb714a8e64e5cc16',
      },
      {
        aad: '436f756e742d30',
        pt: '00010002000300',
        ct: '0be99ddcad54aabf548b3dbae884aff7aaeb0afc9ab60f',
      },
      {
        aad: '00ff00ff00',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: '6b0f4cd351730cd25993d8ad0f11bff1ef2c3a957cb4d8694bb06c60a2f65e4f4cf8c1ae35431071bb18eff3e8',
      },
    ],
    exports: [
      {
        exporter_context: '',
        L: 32,
        exported_value: '3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee',
      },
      {
        exporter_context: '00',
        L: 32,
        exported_value: '2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5',
      },
      {
        exporter_context: '0011002200',
        L: 32,
        exported_value: '73ac25f70dd55c215b4220e6978533ee2d3a559a48c507b11e200af81e64337a',
      },
    ],
  },
  {
    name: 'D.3 Empty info',
    mode: 0x00,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    info: '',
    ikmR: '6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037',
    skRm: '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
    pkRm: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    enc: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    encryptions: [
      {
        aad: '436f756e742d30',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: '2a19b5c53b9bc4d52723cfa64b0c0532b9fd5473e8c1105285be1a5fd763463c3d34236f5d26ebfe906277e094',
      },
    ],
    exports: [
      {
        exporter_context: '54657374436f6e74657874',
        L: 32,
        exported_value: '8a02de446479bb7d27490ed85a69c6bbaddd0969fbc84f7661ab038c9008f053',
      },
    ],
  },
  {
    name: 'D.4 info with Embedded Zero Bytes',
    mode: 0x00,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    info: 'f0000f00ff',
    ikmR: '6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037',
    skRm: '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
    pkRm: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    enc: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    encryptions: [
      {
        aad: '436f756e742d30',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: 'dccc58fdd5dd0f80a162809a6bd47bf881ce2821b5ab718892dd568e2dcef6c98750fa1dc39a6182802ef3416c',
      },
    ],
    exports: [
      {
        exporter_context: '54657374436f6e74657874',
        L: 32,
        exported_value: 'b16979c789e60ff4a21a3975b785ed3114d44525a3f660a4a848891dcf54446a',
      },
    ],
  },
  {
    name: 'D.5 psk and psk_id with Embedded Zero Bytes',
    mode: 0x01,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    info: '4f6465206f6e2061204772656369616e2055726e',
    ikmR: 'd4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098',
    skRm: 'c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd',
    pkRm: '9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366',
    enc: '0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b',
    psk: '0000000000000000111111111111111100000000000000002222222222222222',
    psk_id: '0050534b00696400',
    encryptions: [
      {
        aad: '436f756e742d30',
        pt: '4265617574792069732074727574682c20747275746820626561757479',
        ct: 'cf34c6d0f86cd81c527cff7a2a20541cd017877d6e95f82f9dc13e6937bef65723bf43d4a2362690c20591ce67',
      },
    ],
    exports: [
      {
        exporter_context: '54657374436f6e74657874',
        L: 32,
        exported_value: '000521bf952f7f7c56cf7dbf40ec1f6943a3233abe36a72d20aa4f87e0d90a95',
      },
    ],
  },
]

const implementations: Implementation[] = [
  { name: 'Web Cryptography', KEMS, KDFS, AEADS },
  { name: 'Noble Cryptography', KEMS: NOBLE_KEMS, KDFS: NOBLE_KDFS, AEADS: NOBLE_AEADS },
]

function gte(a: Uint8Array, b: Uint8Array) {
  if (a.byteLength !== b.byteLength) {
    throw new TypeError('byte arrays must have the same length')
  }

  for (let i = 0; i < a.byteLength; i++) {
    const ai = a[i]!
    const bi = b[i]!
    if (ai > bi) return true
    if (ai < bi) return false
  }

  return true
}

async function p256DeriveCandidate(ikm: Uint8Array, counter: number) {
  const kdf = HPKE.KDF_HKDF_SHA256()
  const suiteId = HPKE.concat(HPKE.encode('KEM'), HPKE.I2OSP(0x0010, 2))
  const dkpPrk = await HPKE.LabeledExtract(
    kdf,
    suiteId,
    new Uint8Array(),
    HPKE.encode('dkp_prk'),
    ikm,
  )
  return await HPKE.LabeledExpand(
    kdf,
    suiteId,
    dkpPrk,
    HPKE.encode('candidate'),
    HPKE.I2OSP(counter, 1),
    32,
  )
}

function getSuite(
  impl: Implementation,
  vector: SpecialVector,
): { suite: HPKE.CipherSuite } | { skip: string } {
  const KEM = impl.KEMS.get(vector.kem_id)
  const KDF = impl.KDFS.get(vector.kdf_id)
  const AEAD = impl.AEADS.get(vector.aead_id)

  if (!KEM || !KDF || !AEAD) {
    return { skip: 'not implemented' }
  }

  if (!KEM.supported || !KDF.supported || !AEAD.supported) {
    return { skip: 'not supported' }
  }

  return { suite: new HPKE.CipherSuite(KEM.factory, KDF.factory, AEAD.factory) }
}

async function assertRecipientVector(
  t: test.TestContext,
  suite: HPKE.CipherSuite,
  vector: SpecialVector,
) {
  const kpR = await suite.DeriveKeyPair(hex(vector.ikmR), true)

  t.assert.deepStrictEqual(await suite.SerializePrivateKey(kpR.privateKey), hex(vector.skRm))
  t.assert.deepStrictEqual(await suite.SerializePublicKey(kpR.publicKey), hex(vector.pkRm))

  const psk = vector.psk ? hex(vector.psk) : undefined
  const pskId = vector.psk_id ? hex(vector.psk_id) : undefined
  const ctx = await suite.SetupRecipient(kpR, hex(vector.enc), {
    info: hex(vector.info),
    psk,
    pskId,
  })

  for (const [i, encryption] of vector.encryptions.entries()) {
    t.assert.deepStrictEqual(
      await ctx.Open(hex(encryption.ct), hex(encryption.aad)),
      hex(encryption.pt),
      `encryption ${i}`,
    )
  }

  for (const [i, exported] of vector.exports.entries()) {
    t.assert.deepStrictEqual(
      await ctx.Export(hex(exported.exporter_context), exported.L),
      hex(exported.exported_value),
      `export ${i}`,
    )
  }
}

for (const impl of implementations) {
  test.describe(`special vectors ${impl.name}`, () => {
    test.afterEach(() => setImmediate())

    it(`${P256_REJECTION.section} DeriveKeyPair`, async (t: test.TestContext) => {
      const KEM = impl.KEMS.get(P256_REJECTION.vector.kem_id)
      if (!KEM) {
        t.skip('not implemented')
        return
      }
      if (!KEM.supported) {
        t.skip('not supported')
        return
      }

      const ikm = hex(P256_REJECTION.vector.ikmR)
      const rejected = await p256DeriveCandidate(ikm, 0)
      t.assert.deepStrictEqual(rejected, hex(P256_REJECTION.rejectedCandidate))
      t.assert.ok(gte(rejected, P256_ORDER))

      const accepted = await p256DeriveCandidate(ikm, 1)
      t.assert.deepStrictEqual(accepted, hex(P256_REJECTION.vector.skRm))

      const suite = new HPKE.CipherSuite(KEM.factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
      const kpR = await suite.DeriveKeyPair(ikm, true)
      t.assert.deepStrictEqual(
        await suite.SerializePrivateKey(kpR.privateKey),
        hex(P256_REJECTION.vector.skRm),
      )
      t.assert.deepStrictEqual(
        await suite.SerializePublicKey(kpR.publicKey),
        hex(P256_REJECTION.vector.pkRm),
      )
    })

    for (const vector of SPECIAL_VECTORS) {
      it(vector.name, async (t: test.TestContext) => {
        const result = getSuite(impl, vector)
        if ('skip' in result) {
          t.skip(result.skip)
          return
        }

        await assertRecipientVector(t, result.suite, vector)
      })
    }
  })
}
