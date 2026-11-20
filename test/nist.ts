import it, * as test from 'node:test'
import assert from 'node:assert/strict'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import * as HPKE from '../index.ts'
import * as noble from '../examples/noble-suite/index.ts'
import { hex, supported } from './support.ts'
// @ts-expect-error: shared with the browser runner
import { checkNistKeys } from './nist-keys.js'

it('NIST private scalar imports match independent reference points', async () => {
  await checkNistKeys(HPKE)
})

it('NIST public point recovery when scalar-only PKCS8 JWK export is unavailable', async (t: test.TestContext) => {
  t.after(() => t.mock.restoreAll())
  const descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, 'getPublicKey')
  Object.defineProperty(crypto.subtle, 'getPublicKey', { value: undefined, configurable: true })
  t.after(() => {
    if (descriptor) Object.defineProperty(crypto.subtle, 'getPublicKey', descriptor)
    else Reflect.deleteProperty(crypto.subtle, 'getPublicKey')
  })
  const imported = new WeakSet<CryptoKey>()
  const importKey = crypto.subtle.importKey.bind(crypto.subtle)
  const exportKey = crypto.subtle.exportKey.bind(crypto.subtle)
  let recoveries = 0
  t.mock.method(crypto.subtle, 'importKey', async (...args: unknown[]) => {
    const key = (await Reflect.apply(importKey, undefined, args)) as CryptoKey
    if (args[0] === 'pkcs8' && key.algorithm.name === 'ECDH') imported.add(key)
    return key
  })
  t.mock.method(crypto.subtle, 'exportKey', async (...args: unknown[]) => {
    if (args[0] === 'jwk' && imported.has(args[1] as CryptoKey)) {
      recoveries++
      throw new DOMException('Public coordinates unavailable', 'OperationError')
    }
    return Reflect.apply(exportKey, undefined, args)
  })
  await checkNistKeys(HPKE)
  t.assert.ok(recoveries > 0)
})

it('NIST import does not retry unexpected failures', async (t: test.TestContext) => {
  t.after(() => t.mock.restoreAll())
  const cause = new Error('Unexpected import failure')
  const mocked = t.mock.method(crypto.subtle, 'importKey', async () => {
    throw cause
  })
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_P256_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_128_GCM,
  )
  const scalar = new Uint8Array(32)
  scalar[31] = 1
  await t.assert.rejects(suite.DeserializePrivateKey(scalar), (error: Error) => {
    t.assert.equal(error.cause, cause)
    return true
  })
  t.assert.equal(mocked.mock.callCount(), 1)
})

it('NIST native public key extraction preserves the imported private key', async (t: test.TestContext) => {
  t.after(() => t.mock.restoreAll())
  // @ts-expect-error
  if (typeof crypto.subtle.getPublicKey !== 'function') return t.skip('getPublicKey unavailable')
  const importKey = crypto.subtle.importKey.bind(crypto.subtle)
  const imported: CryptoKey[] = []
  t.mock.method(crypto.subtle, 'importKey', async (...args: unknown[]) => {
    const key = await Reflect.apply(importKey, undefined, args)
    if (key.algorithm.name === 'ECDH') imported.push(key)
    return key
  })
  const kem = HPKE.KEM_DHKEM_P256_HKDF_SHA256()
  for (const extractable of [false, true]) {
    imported.length = 0
    const pair = await kem.DeriveKeyPair(new Uint8Array(32), extractable)
    t.assert.equal(imported.length, 1)
    t.assert.equal(pair.privateKey, imported[0])
    t.assert.equal(pair.privateKey.extractable, extractable)
    t.assert.equal(pair.publicKey.extractable, true)
  }
})

for (const [factoryName, curve, kdfFactory] of [
  ['KEM_DHKEM_P256_HKDF_SHA256', p256, HPKE.KDF_HKDF_SHA256],
  ['KEM_DHKEM_P384_HKDF_SHA384', p384, HPKE.KDF_HKDF_SHA384],
  ['KEM_DHKEM_P521_HKDF_SHA512', p521, HPKE.KDF_HKDF_SHA512],
] as const) {
  it(`${factoryName} validates noble private scalars`, async () => {
    const suite = new HPKE.CipherSuite(
      noble[factoryName],
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_EXPORT_ONLY,
    )
    const order = curve.Point.Fn.ORDER
    const encodeScalar = (scalar: bigint) =>
      hex(scalar.toString(16).padStart(suite.KEM.Nsk * 2, '0'))

    for (const scalar of [0n, order, order + 1n]) {
      await assert.rejects(suite.DeserializePrivateKey(encodeScalar(scalar)), (error: unknown) => {
        assert.ok(error instanceof HPKE.DeserializeError)
        assert.ok(error.cause instanceof Error)
        assert.equal(error.cause.message, 'Invalid scalar')
        return true
      })
    }

    for (const scalar of [1n, order - 1n]) {
      const encoded = encodeScalar(scalar)
      const key = await suite.DeserializePrivateKey(encoded, true)
      assert.deepEqual(await suite.SerializePrivateKey(key), encoded)
    }
  })

  for (const [implementationName, implementation] of [
    ['WebCrypto', HPKE],
    ['noble', noble],
  ] as const) {
    it(`${implementationName} ${factoryName} accepts a finite zero-x DH point`, async () => {
      const kem: HPKE.KEM = implementation[factoryName]()
      const scalar = new Uint8Array(kem.Nsk)
      scalar[scalar.length - 1] = 1
      const compressed = new Uint8Array(kem.Nsk + 1)
      compressed[0] = 2
      const encapsulatedSecret = curve.Point.fromBytes(compressed).toBytes(false)
      const privateKey = await kem.DeserializePrivateKey(scalar, true)

      const kdf = kdfFactory()
      const suiteId = HPKE.concat(HPKE.encode('KEM'), HPKE.I2OSP(kem.id, 2))
      const prk = await HPKE.LabeledExtract(
        kdf,
        suiteId,
        new Uint8Array(),
        HPKE.encode('eae_prk'),
        new Uint8Array(kem.Nsk),
      )
      const expected = await HPKE.LabeledExpand(
        kdf,
        suiteId,
        prk,
        HPKE.encode('shared_secret'),
        HPKE.concat(encapsulatedSecret, curve.getPublicKey(scalar, false)),
        kem.Nsecret,
      )
      assert.deepEqual(await kem.Decap(encapsulatedSecret, privateKey, undefined), expected)
    })
  }
}

for (const factoryName of ['KEM_DHKEM_X25519_HKDF_SHA256', 'KEM_DHKEM_X448_HKDF_SHA512'] as const) {
  for (const [implementationName, implementation] of [
    ['WebCrypto', HPKE],
    ['noble', noble],
  ] as const) {
    it(
      `${implementationName} ${factoryName} rejects low-order public keys`,
      { skip: implementationName === 'WebCrypto' && !supported[factoryName]!() },
      async () => {
        const factory: HPKE.KEMFactory = implementation[factoryName]
        const suite = new HPKE.CipherSuite(factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
        const recipient = await suite.GenerateKeyPair(true)
        const publicKey = await suite.DeserializePublicKey(new Uint8Array(suite.KEM.Npk))

        await assert.rejects(suite.SetupSender(publicKey))
        await assert.rejects(suite.SetupRecipient(recipient, new Uint8Array(suite.KEM.Nenc)))
      },
    )
  }
}

// xWhereYIsOne solves x^3 - 3x + b = 1 modulo p. Choosing x = 0 on one point and
// y = 1 on another lets us add p to either coordinate without overflowing its encoding.
for (const [factoryName, curve, xWhereYIsOne] of [
  [
    'KEM_DHKEM_P256_HKDF_SHA256',
    p256,
    0x09e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96cn,
  ],
  [
    'KEM_DHKEM_P384_HKDF_SHA384',
    p384,
    0x2261b2bf605c22f2f3aef6338719b2c486388ad5240719a5257315969ef01ba27f0a104c89704773a81fdabee6ab5c78n,
  ],
  [
    'KEM_DHKEM_P521_HKDF_SHA512',
    p521,
    0x00d9cb7a32dab342f863edb340f3ea61ddf833e755ce66bb1a918a42714ba05bcdf4ff10994f616a9d80cd0b48b326e3a8a2a8f5634d824875b6e71fb7cddd7b5018n,
  ],
] as const) {
  const { BASE: G, Fp } = curve.Point
  const coordinate = (n: bigint) => hex(n.toString(16).padStart(Fp.BYTES * 2, '0'))
  const encode = (x: bigint, y: bigint, prefix = 0x04) =>
    HPKE.concat(Uint8Array.of(prefix), coordinate(x), coordinate(y))
  const zeroX = curve.Point.fromBytes(HPKE.concat(Uint8Array.of(0x02), coordinate(0n)))
  const valid = [
    ['generator', G.toBytes(false)],
    ['point with x = 0', zeroX.toBytes(false)],
    ['point with y = 1', encode(xWhereYIsOne, 1n)],
  ] as const
  const invalid = [
    ['all-zero bytes', new Uint8Array(1 + 2 * Fp.BYTES)],
    ['zero coordinates', encode(0n, 0n)],
    ['off-curve point', encode(G.x, (G.y + 1n) % Fp.ORDER)],
    ['x = 0 encoded as p', encode(Fp.ORDER, zeroX.y)],
    ['y = 1 encoded as p + 1', encode(xWhereYIsOne, Fp.ORDER + 1n)],
    ['hybrid encoding', encode(G.x, G.y, 0x06 | Number(G.y & 1n))],
    ['compressed encoding', G.toBytes(true)],
  ] as const

  for (const [implementationName, implementation] of [
    ['WebCrypto', HPKE],
    ['noble', noble],
  ] as const) {
    const factory: HPKE.KEMFactory = implementation[factoryName]
    const suite = new HPKE.CipherSuite(factory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_EXPORT_ONLY)
    it(`${implementationName} ${factoryName} accepts valid public point encodings`, async () => {
      const recipient = await suite.GenerateKeyPair()

      for (const [name, bytes] of valid) {
        const key = await suite.DeserializePublicKey(bytes)
        assert.deepEqual(await suite.SerializePublicKey(key), bytes, name)
        await assert.doesNotReject(suite.SetupRecipient(recipient, bytes), name)
      }
    })

    for (const [name, bytes] of invalid) {
      // Deno accepts uncompressed points with invalid coordinates on import.
      // https://github.com/denoland/deno/pull/37211
      const todo = 'Deno' in globalThis && implementation === HPKE && bytes[0] === 0x04
      it(`${implementationName} ${factoryName} rejects ${name}`, { todo }, async () => {
        await assert.rejects(suite.DeserializePublicKey(bytes), {
          name: 'DeserializeError',
          message: 'Public key deserialization failed',
        })
        const recipient = await suite.GenerateKeyPair()
        await assert.rejects(suite.SetupRecipient(recipient, bytes), { name: 'DecapError' })
      })
    }
  }
}
