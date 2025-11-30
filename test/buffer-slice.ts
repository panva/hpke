/**
 * Tests for Node.js Buffer.prototype.slice() compatibility.
 *
 * Node.js Buffer is an instance of Uint8Array, but its .slice() method returns a view that shares
 * memory with the original buffer (like Uint8Array.prototype.subarray()), while
 * Uint8Array.prototype.slice() returns a new array with copied data.
 *
 * This difference can cause issues when user input (which may be a Buffer) is sliced and the
 * original buffer is subsequently modified.
 */
import it, * as test from 'node:test'
import { strict as assert } from 'node:assert'

import * as HPKE from '../index.ts'
import { supported } from './support.ts'

test.describe('Buffer.prototype.slice() compatibility', () => {
  const run = supported.KEM_MLKEM768_X25519() ? it : it.skip
  test.describe('Hybrid KEM DeserializePrivateKey', () => {
    run(
      'should not be affected by modifications to the original Buffer after deserialization',
      async () => {
        const suite = new HPKE.CipherSuite(
          HPKE.KEM_MLKEM768_X25519,
          HPKE.KDF_HKDF_SHA256,
          HPKE.AEAD_AES_128_GCM,
        )

        // Generate an extractable key pair and serialize the private key
        const keyPair = await suite.GenerateKeyPair(true)
        const serialized = await suite.SerializePrivateKey(keyPair.privateKey)

        // Create a Buffer from the serialized key (simulating user input as Buffer)
        const bufferInput = Buffer.from(serialized)

        // Deserialize the private key from the Buffer
        const deserializedKey = await suite.DeserializePrivateKey(bufferInput, true)

        // Now modify the original buffer - this simulates the user reusing/modifying their buffer
        bufferInput.fill(0)

        // Serialize the deserialized key - if the internal storage shares memory with
        // the original buffer, this will return zeros instead of the original key material
        const reserialized = await suite.SerializePrivateKey(deserializedKey)

        // The reserialized key should match the original, not the zeroed buffer
        // Compare as Uint8Array to avoid Buffer vs Uint8Array type mismatch
        assert.deepEqual(
          new Uint8Array(reserialized),
          new Uint8Array(serialized),
          'Deserialized key should not be affected by modifications to the original Buffer',
        )
      },
    )
  })

  test.describe('Hybrid KEM Decap (split function)', () => {
    run('should use copied data, not views that can be corrupted', async () => {
      const suite = new HPKE.CipherSuite(
        HPKE.KEM_MLKEM768_X25519,
        HPKE.KDF_HKDF_SHA256,
        HPKE.AEAD_AES_128_GCM,
      )

      // Generate recipient key pair
      const recipient = await suite.GenerateKeyPair()

      // Encrypt a message
      const plaintext = new TextEncoder().encode('Hello, World!')
      const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext)

      // Create a Buffer from the encapsulated secret (simulating user input as Buffer)
      const encBuffer = Buffer.from(encapsulatedSecret)

      // Start decryption - internally this calls split() on encBuffer
      // The split function slices the buffer into [ct_PQ, ct_T]
      // If split returns views (Buffer.slice behavior), corrupting encBuffer
      // during the async decryption will cause failure
      const openPromise = suite.Open(recipient.privateKey, encBuffer, ciphertext)

      // Immediately corrupt the buffer - if split() returned views, this corruption
      // would affect the ct_PQ and ct_T that are being used for decryption
      encBuffer.fill(0)

      // The decryption should still succeed if split() made proper copies
      // If split() returned views, the corruption above will cause decryption to fail
      // with a DecapError because the cryptographic operations will fail
      await assert.doesNotReject(
        openPromise,
        'Decryption should succeed even when input buffer is corrupted after call',
      )
    })
  })

  test.describe('Hybrid KEM SerializePrivateKey (getSeed)', () => {
    run(
      'should return independent copies that do not share memory with internal state',
      async () => {
        const suite = new HPKE.CipherSuite(
          HPKE.KEM_MLKEM768_X25519,
          HPKE.KDF_HKDF_SHA256,
          HPKE.AEAD_AES_128_GCM,
        )

        // Generate an extractable key pair and serialize
        const keyPair = await suite.GenerateKeyPair(true)
        const originalSerialized = await suite.SerializePrivateKey(keyPair.privateKey)

        // Deserialize from a Buffer (simulating user input)
        const bufferInput = Buffer.from(originalSerialized)
        const deserializedKey = await suite.DeserializePrivateKey(bufferInput, true)

        // Serialize the deserialized key - getSeed() is called internally
        const serialized1 = await suite.SerializePrivateKey(deserializedKey)

        // Modify the returned serialization - if getSeed returns a view of internal state,
        // this could corrupt the internal seed
        serialized1.fill(0)

        // Serialize again - if getSeed() returns views sharing memory, this will be affected
        const serialized2 = await suite.SerializePrivateKey(deserializedKey)

        // The second serialization should match the original, not the zeroed value
        // Compare as Uint8Array to avoid Buffer vs Uint8Array type mismatch
        assert.deepEqual(
          new Uint8Array(serialized2),
          new Uint8Array(originalSerialized),
          'SerializePrivateKey should return independent copies that do not affect internal state',
        )
      },
    )
  })
})
