import it, * as test from 'node:test'

import * as HPKE from '../index.ts'
import { hex } from './support.ts'

const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

test.describe('IncrementSeq', () => {
  it('Context seq is 0 before first message and 1 after it', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Check that seq is 0 before first message
    t.assert.strictEqual(contextS.seq, 0)
    t.assert.strictEqual(contextR.seq, 0)

    // Send first message
    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)
    await contextR.Open(ct, aad)

    // Check that seq is 1 after first message
    t.assert.strictEqual(contextS.seq, 1)
    t.assert.strictEqual(contextR.seq, 1)
  })

  it.skip('Recipient cannot call open() the same message twice unless re-sequenced', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Send and receive first message
    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)
    const decrypted1 = await contextR.Open(ct, aad)
    t.assert.deepStrictEqual(decrypted1, pt)

    // Attempt to open the same ciphertext again - should fail
    await t.assert.rejects(contextR.Open(ct, aad), HPKE.OpenError)

    // Re-sequence back to 0
    // @ts-expect-error
    contextR.seq = 0
    t.assert.strictEqual(contextR.seq, 0)

    // Now the same ciphertext can be opened again
    const decrypted2 = await contextR.Open(ct, aad)
    t.assert.deepStrictEqual(decrypted2, pt)

    // Verify seq is now 1 again
    t.assert.strictEqual(contextR.seq, 1)
  })

  it('Concurrent Seal() calls must not reuse sequence numbers (race condition test)', async (t: test.TestContext) => {
    // This test verifies that concurrent calls to Seal() don't cause a race condition
    // where multiple calls read the same sequence number before any of them increment it.
    // If there's a race condition, multiple messages would use the same nonce.

    const kp = await suite.DeriveKeyPair(new Uint8Array(suite.KEM.Nsk))
    const pkR = kp.publicKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(kp, enc)

    const aad = new Uint8Array([1, 2, 3])
    const numConcurrentCalls = 10

    // Create unique plaintexts
    const plaintexts = Array.from(
      { length: numConcurrentCalls },
      (_, i) => new Uint8Array([i, i, i, i]),
    )

    // Call Seal() concurrently without awaiting
    const sealPromises = plaintexts.map((pt) => contextS.Seal(pt, aad))

    // Wait for all to complete
    const ciphertexts = await Promise.all(sealPromises)

    // Verify the final sequence number is correct
    t.assert.strictEqual(contextS.seq, numConcurrentCalls)

    // All ciphertexts should be different (if same nonce was used, identical plaintexts
    // would produce identical ciphertexts, though this isn't guaranteed)
    const uniqueCiphertexts = new Set(ciphertexts.map((ct) => ct.join(',')))
    t.assert.strictEqual(uniqueCiphertexts.size, numConcurrentCalls)

    // Most importantly: verify that all messages can be decrypted in order
    // This will fail if any sequence numbers were reused, because the recipient
    // will be expecting sequential nonces
    for (let i = 0; i < numConcurrentCalls; i++) {
      const decrypted = await contextR.Open(ciphertexts[i]!, aad)
      t.assert.deepStrictEqual(decrypted, plaintexts[i])
    }
  })

  it('Failed Open() does not increment sequence number', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)

    // Verify seq is 0
    t.assert.strictEqual(contextR.seq, 0)

    // Tamper with the ciphertext
    const badCt = new Uint8Array(ct)
    badCt[0]! ^= 0xff

    // Attempt to open with bad ciphertext - should fail
    await t.assert.rejects(contextR.Open(badCt, aad), HPKE.OpenError)

    // Sequence number should still be 0
    t.assert.strictEqual(contextR.seq, 0)

    // Now open with the correct ciphertext - should succeed
    const decrypted = await contextR.Open(ct, aad)
    t.assert.deepStrictEqual(decrypted, pt)

    // Now sequence should be 1
    t.assert.strictEqual(contextR.seq, 1)
  })

  it('Export() does not increment sequence number', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Verify initial sequence is 0
    t.assert.strictEqual(contextS.seq, 0)
    t.assert.strictEqual(contextR.seq, 0)

    // Export from sender context
    const exporterContext = new Uint8Array([7, 8, 9])
    const exportedS1 = await contextS.Export(exporterContext, 32)
    t.assert.strictEqual(exportedS1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextS.seq, 0)

    // Export from recipient context
    const exportedR1 = await contextR.Export(exporterContext, 32)
    t.assert.strictEqual(exportedR1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextR.seq, 0)
  })

  it.skip('seq can be set to MAX_SAFE_INTEGER', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Should accept MAX_SAFE_INTEGER as a number
    // @ts-expect-error
    contextR.seq = Number.MAX_SAFE_INTEGER
    t.assert.strictEqual(contextR.seq, Number.MAX_SAFE_INTEGER)
  })

  it.skip('seq cannot be set to floats or negative numbers', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Reject float values
    t.assert.throws(
      () => {
        // @ts-expect-error
        contextR.seq = 3.14
      },
      {
        message: 'seq must be a non-negative safe integer or a BigInt',
        name: 'TypeError',
      },
    )

    // Reject negative numbers
    t.assert.throws(
      () => {
        // @ts-expect-error
        contextR.seq = -1
      },
      {
        message: 'seq must be a non-negative safe integer or a BigInt',
        name: 'TypeError',
      },
    )

    // Reject negative numbers
    t.assert.throws(
      () => {
        // @ts-expect-error
        contextR.seq = -1
      },
      {
        message: 'seq must be a non-negative safe integer or a BigInt',
        name: 'TypeError',
      },
    )

    // Reject numbers greater than MAX_SAFE_INTEGER
    t.assert.throws(
      () => {
        // @ts-expect-error
        contextR.seq = Number.MAX_SAFE_INTEGER + 1
      },
      {
        message: 'seq must be a non-negative safe integer or a BigInt',
        name: 'TypeError',
      },
    )
  })

  it.skip('seq can be set to a BigInt', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Should accept small number values
    // @ts-expect-error
    contextR.seq = 42
    t.assert.strictEqual(contextR.seq, 42)
  })

  it.skip('internal seq can deal with numbers beyond Number.MAX_SAFE_INTEGER', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const skR = kp.privateKey
    const enc = hex(
      '04cfacd248a4b530c1666f1a46d7671addcfd8c47ab7290964a97343d8f74659233e5d939307696ffc6d81a8f0eb0765932e7b45cb366c976af9d0acfa7e381f16',
    )
    const contextR = await suite.SetupRecipient(skR, enc)

    // Set seq to MAX_SAFE_INTEGER
    // @ts-expect-error
    contextR.seq = Number.MAX_SAFE_INTEGER

    // Exchange first message
    const aad1 = new Uint8Array([1, 2, 3])
    const pt1 = new Uint8Array([4, 5, 6])
    const ct1 = hex('66179357f188959e2e587fa7382fd4f4ca3b7e')
    const decrypted1 = await contextR.Open(ct1, aad1)
    t.assert.deepStrictEqual(decrypted1, pt1)

    // Exchange second message
    const aad2 = new Uint8Array([7, 8, 9])
    const pt2 = new Uint8Array([10, 11, 12])
    const ct2 = hex('cd4a54dc49b1f9acdfc3cfdf9ef85edf47d35a')
    const decrypted2 = await contextR.Open(ct2, aad2)
    t.assert.deepStrictEqual(decrypted2, pt2)
  })

  // This test would require running 2^53 - 1 messages which is not practical
  it.skip('seq reaches MAX_SAFE_INTEGER and throws MessageLimitReachedError', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulated_key: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Would need to set seq to MAX_SAFE_INTEGER - 1 and then call Seal()
    // But since the seq setter is removed, this would require running 2^53 - 1 messages
    // which is not practical for testing

    // If seq setter were available:
    // @ts-ignore
    // contextS.seq = Number.MAX_SAFE_INTEGER - 1

    // First message should succeed (seq will be MAX_SAFE_INTEGER)
    const aad1 = new Uint8Array([1, 2, 3])
    const pt1 = new Uint8Array([4, 5, 6])
    const ct1 = await contextS.Seal(pt1, aad1)
    const decrypted1 = await contextR.Open(ct1, aad1)
    t.assert.deepStrictEqual(decrypted1, pt1)

    // Second message should fail - attempting to increment beyond MAX_SAFE_INTEGER
    const aad2 = new Uint8Array([13, 14, 15])
    const pt2 = new Uint8Array([16, 17, 18])
    await t.assert.rejects(contextS.Seal(pt2, aad2), HPKE.MessageLimitReachedError)
  })
})
