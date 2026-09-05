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

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
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

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
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

  it('sender and recipient retain separate operation APIs and state', async (t: test.TestContext) => {
    const recipient = await suite.GenerateKeyPair()
    const options = { psk: new Uint8Array(32).fill(17), pskId: HPKE.encode('sequence test') }
    const { encapsulatedSecret, ctx: sender } = await suite.SetupSender(
      recipient.publicKey,
      options,
    )
    const receiver = await suite.SetupRecipient(recipient, encapsulatedSecret, options)

    t.assert.equal('Open' in sender, false)
    t.assert.equal('Seal' in receiver, false)
    t.assert.equal(sender.mode, HPKE.MODE_PSK)
    t.assert.equal(receiver.mode, HPKE.MODE_PSK)
    t.assert.equal(sender.Nt, suite.AEAD.Nt)
    const plaintext = HPKE.encode('independent context state')
    const ciphertext = await sender.Seal(plaintext)
    t.assert.equal(sender.seq, 1)
    t.assert.equal(receiver.seq, 0)
    t.assert.deepEqual(await receiver.Open(ciphertext), plaintext)
    t.assert.equal(receiver.seq, 1)
  })

  it('failed Seal releases the queue without advancing the sequence', async (t: test.TestContext) => {
    const aead = HPKE.AEAD_AES_128_GCM()
    const failure = new RangeError('test encryption failure')
    const factory: HPKE.AEADFactory = () => ({
      ...aead,
      async Seal(key, nonce, aad, plaintext) {
        if (plaintext[0] === 0xff) throw failure
        return aead.Seal(key, nonce, aad, plaintext)
      },
    })
    const localSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      factory,
    )
    const recipient = await localSuite.GenerateKeyPair()
    const { encapsulatedSecret, ctx: sender } = await localSuite.SetupSender(recipient.publicKey)
    const receiver = await localSuite.SetupRecipient(recipient, encapsulatedSecret)
    const plaintext = HPKE.encode('queued encryption')
    const rejected = t.assert.rejects(sender.Seal(Uint8Array.of(0xff)), failure)
    const pending = sender.Seal(plaintext)
    await rejected
    const ciphertext = await pending

    t.assert.equal(sender.seq, 1)
    t.assert.deepEqual(await receiver.Open(ciphertext), plaintext)
  })

  it('failed Open releases the queue without advancing the sequence', async (t: test.TestContext) => {
    const recipient = await suite.GenerateKeyPair()
    const { encapsulatedSecret, ctx: sender } = await suite.SetupSender(recipient.publicKey)
    const receiver = await suite.SetupRecipient(recipient, encapsulatedSecret)
    const plaintext = HPKE.encode('queued decryption')
    const ciphertext = await sender.Seal(plaintext)
    const invalid = new Uint8Array(ciphertext)
    invalid[0]! ^= 1

    const rejected = t.assert.rejects(receiver.Open(invalid), HPKE.OpenError)
    const pending = receiver.Open(ciphertext)
    await rejected
    t.assert.deepEqual(await pending, plaintext)
    t.assert.equal(receiver.seq, 1)
  })

  it('both context roles reject sequence overflow without wrapping', async (t: test.TestContext) => {
    const factory: HPKE.AEADFactory = () => ({
      id: 0xfffe,
      type: 'AEAD',
      name: 'Sequence test AEAD',
      Nk: 16,
      Nn: 1,
      Nt: 0,
      async Seal(_key, _nonce, _aad, plaintext) {
        return plaintext
      },
      async Open(_key, _nonce, _aad, ciphertext) {
        return ciphertext
      },
    })
    const localSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      factory,
    )
    const recipient = await localSuite.GenerateKeyPair()
    const { encapsulatedSecret, ctx: sender } = await localSuite.SetupSender(recipient.publicKey)
    const receiver = await localSuite.SetupRecipient(recipient, encapsulatedSecret)
    const plaintext = Uint8Array.of(17)
    for (let sequence = 0; sequence < 255; sequence++) {
      await receiver.Open(await sender.Seal(plaintext))
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      await t.assert.rejects(sender.Seal(plaintext), HPKE.MessageLimitReachedError)
      await t.assert.rejects(receiver.Open(plaintext), HPKE.MessageLimitReachedError)
      t.assert.equal(sender.seq, 255)
      t.assert.equal(receiver.seq, 255)
    }
  })
})
