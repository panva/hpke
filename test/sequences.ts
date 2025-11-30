import it, * as test from 'node:test'

import * as HPKE from '../index.ts'

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

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Check that seq is 0 before first message
    t.assert.strictEqual(contextS.seq, 0n)
    t.assert.strictEqual(contextR.seq, 0n)

    // Send first message
    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)
    await contextR.Open(ct, aad)

    // Check that seq is 1 after first message
    t.assert.strictEqual(contextS.seq, 1n)
    t.assert.strictEqual(contextR.seq, 1n)
  })

  it('Concurrent Seal() calls must not reuse sequence numbers (race condition test)', async (t: test.TestContext) => {
    // This test verifies that concurrent calls to Seal() don't cause a race condition
    // where multiple calls read the same sequence number before any of them increment it.
    // If there's a race condition, multiple messages would use the same nonce.

    const kp = await suite.DeriveKeyPair(new Uint8Array(suite.KEM.Nsk))
    const pkR = kp.publicKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
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
    t.assert.strictEqual(contextS.seq, BigInt(numConcurrentCalls))

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

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)

    // Verify seq is 0
    t.assert.strictEqual(contextR.seq, 0n)

    // Tamper with the ciphertext
    const badCt = new Uint8Array(ct)
    badCt[0]! ^= 0xff

    // Attempt to open with bad ciphertext - should fail
    await t.assert.rejects(contextR.Open(badCt, aad), HPKE.OpenError)

    // Sequence number should still be 0
    t.assert.strictEqual(contextR.seq, 0n)

    // Now open with the correct ciphertext - should succeed
    const decrypted = await contextR.Open(ct, aad)
    t.assert.deepStrictEqual(decrypted, pt)

    // Now sequence should be 1
    t.assert.strictEqual(contextR.seq, 1n)
  })

  it('Export() does not increment sequence number', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Verify initial sequence is 0
    t.assert.strictEqual(contextS.seq, 0n)
    t.assert.strictEqual(contextR.seq, 0n)

    // Export from sender context
    const exporterContext = new Uint8Array([7, 8, 9])
    const exportedS1 = await contextS.Export(exporterContext, 32)
    t.assert.strictEqual(exportedS1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextS.seq, 0n)

    // Export from recipient context
    const exportedR1 = await contextR.Export(exporterContext, 32)
    t.assert.strictEqual(exportedR1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextR.seq, 0n)
  })
})
