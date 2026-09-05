import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as HPKE from '../index.ts'
import { supported } from './support.ts'

const empty = new Uint8Array()

for (const factory of [HPKE.KDF_HKDF_SHA256, HPKE.KDF_HKDF_SHA384, HPKE.KDF_HKDF_SHA512]) {
  for (const useBuffer of [false, true]) {
    test(`${factory.name} honors ${useBuffer ? 'Buffer' : 'Uint8Array'} PRK changes`, async () => {
      const kdf = factory()
      const prk = useBuffer ? Buffer.alloc(kdf.Nh, 17) : new Uint8Array(kdf.Nh).fill(17)
      const original = await kdf.Expand(prk, empty, kdf.Nh + 1)
      prk.fill(34)

      const actual = await kdf.Expand(prk, empty, kdf.Nh + 1)
      const expected = await kdf.Expand(new Uint8Array(prk), empty, kdf.Nh + 1)
      assert.deepEqual(actual, expected)
      assert.notDeepEqual(actual, original)
    })
  }
}

for (const factory of [HPKE.AEAD_AES_128_GCM, HPKE.AEAD_AES_256_GCM, HPKE.AEAD_ChaCha20Poly1305]) {
  for (const useBuffer of [false, true]) {
    test(
      `${factory.name} honors ${useBuffer ? 'Buffer' : 'Uint8Array'} key changes`,
      { skip: supported[factory.name]!() ? false : 'AEAD is unsupported in this runtime' },
      async () => {
        const aead = factory()
        const key = useBuffer ? Buffer.alloc(aead.Nk, 17) : new Uint8Array(aead.Nk).fill(17)
        const nonce = new Uint8Array(aead.Nn)
        const plaintext = HPKE.encode('updated AEAD key')
        await aead.Seal(key, nonce, empty, plaintext)
        key.fill(34)
        nonce[nonce.length - 1] = 1

        const expected = await aead.Seal(new Uint8Array(key), nonce, empty, plaintext)
        assert.deepEqual(await aead.Seal(key, nonce, empty, plaintext), expected)
        assert.deepEqual(await aead.Open(key, nonce, empty, expected), plaintext)

        key.fill(51)
        nonce[nonce.length - 1] = 2
        const ciphertext = await aead.Seal(new Uint8Array(key), nonce, empty, plaintext)
        assert.deepEqual(await aead.Open(key, nonce, empty, ciphertext), plaintext)
      },
    )
  }
}

test('HKDF reuses imports only while PRK bytes are unchanged', async (context) => {
  const kdf = HPKE.KDF_HKDF_SHA256()
  const prk = new Uint8Array(kdf.Nh).fill(17)
  const imports = context.mock.method(crypto.subtle, 'importKey')

  await Promise.all([kdf.Expand(prk, empty, 32), kdf.Expand(prk, empty, 64)])
  await kdf.Expand(prk, empty, 32)
  assert.equal(imports.mock.callCount(), 1)

  prk[0] = 34
  await kdf.Expand(prk, empty, 32)
  assert.equal(imports.mock.callCount(), 2)
})

test('AEAD reuses imports only while key bytes are unchanged', async (context) => {
  const aead = HPKE.AEAD_AES_128_GCM()
  const key = new Uint8Array(aead.Nk).fill(17)
  const nonce = new Uint8Array(aead.Nn)
  const imports = context.mock.method(crypto.subtle, 'importKey')

  const ciphertext = await aead.Seal(key, nonce, empty, empty)
  await aead.Open(key, nonce, empty, ciphertext)
  assert.equal(imports.mock.callCount(), 1)

  key[0] = 34
  nonce[nonce.length - 1] = 1
  await aead.Seal(key, nonce, empty, empty)
  assert.equal(imports.mock.callCount(), 2)
})

test('concurrent AEAD calls share an unchanged key import', async (context) => {
  const aead = HPKE.AEAD_AES_128_GCM()
  const key = new Uint8Array(aead.Nk).fill(17)
  const imports = context.mock.method(crypto.subtle, 'importKey')

  await Promise.all(
    [0, 1].map((sequence) => aead.Seal(key, HPKE.I2OSP(sequence, aead.Nn), empty, empty)),
  )
  assert.equal(imports.mock.callCount(), 1)
})

test('HKDF retries a failed key import', async (context) => {
  const kdf = HPKE.KDF_HKDF_SHA256()
  const prk = new Uint8Array(kdf.Nh).fill(17)
  const failure = new DOMException('key import failed', 'OperationError')
  const imports = context.mock.method(crypto.subtle, 'importKey')
  imports.mock.mockImplementationOnce(async () => {
    throw failure
  })

  await assert.rejects(kdf.Expand(prk, empty, 32), failure)
  assert.equal((await kdf.Expand(prk, empty, 32)).byteLength, 32)
  assert.equal(imports.mock.callCount(), 2)
})

test('AEAD retries a failed key import', async (context) => {
  const aead = HPKE.AEAD_AES_128_GCM()
  const key = new Uint8Array(aead.Nk).fill(17)
  const nonce = new Uint8Array(aead.Nn)
  const failure = new DOMException('key import failed', 'OperationError')
  const imports = context.mock.method(crypto.subtle, 'importKey')
  imports.mock.mockImplementationOnce(async () => {
    throw failure
  })

  await assert.rejects(aead.Seal(key, nonce, empty, empty), failure)
  assert.equal((await aead.Seal(key, nonce, empty, empty)).byteLength, aead.Nt)
  assert.equal(imports.mock.callCount(), 2)
})
