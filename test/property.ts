import assert from 'node:assert/strict'
import { test } from 'node:test'

import fc from 'fast-check'

import * as HPKE from '../index.ts'

const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)
const bytes = fc.uint8Array({ maxLength: 4096 })
const metadata = fc.uint8Array({ maxLength: 512 })
const options = { numRuns: 50 }

function different(input: Uint8Array): Uint8Array {
  const output = new Uint8Array(input.byteLength + 1)
  output.set(input)
  output[input.byteLength] = 1
  return output
}

test('Seal and Open preserve arbitrary plaintext, AAD, and info', async () => {
  const recipient = await suite.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(bytes, metadata, metadata, async (plaintext, aad, info) => {
      const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext, {
        aad,
        info,
      })

      assert.deepEqual(
        await suite.Open(recipient, encapsulatedSecret, ciphertext, { aad, info }),
        plaintext,
      )
    }),
    options,
  )
})

test('Open rejects modified ciphertext, AAD, and info', async () => {
  const recipient = await suite.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(
      bytes,
      metadata,
      metadata,
      fc.nat(),
      async (plaintext, aad, info, position) => {
        const { encapsulatedSecret, ciphertext } = await suite.Seal(
          recipient.publicKey,
          plaintext,
          { aad, info },
        )
        const tampered = ciphertext.slice()
        tampered[position % tampered.byteLength]! ^= 1 << (position % 8)

        await assert.rejects(
          suite.Open(recipient, encapsulatedSecret, tampered, { aad, info }),
          HPKE.OpenError,
        )
        await assert.rejects(
          suite.Open(recipient, encapsulatedSecret, ciphertext, {
            aad: different(aad),
            info,
          }),
          HPKE.OpenError,
        )
        await assert.rejects(
          suite.Open(recipient, encapsulatedSecret, ciphertext, {
            aad,
            info: different(info),
          }),
          HPKE.OpenError,
        )
      },
    ),
    options,
  )
})

test('sender and recipient contexts agree on exported secrets', async () => {
  const recipient = await suite.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(
      metadata,
      metadata,
      fc.integer({ min: 1, max: 128 }),
      async (info, exporterContext, length) => {
        const { encapsulatedSecret, ctx: sender } = await suite.SetupSender(recipient.publicKey, {
          info,
        })
        const receiver = await suite.SetupRecipient(recipient, encapsulatedSecret, {
          info,
        })

        assert.deepEqual(
          await receiver.Export(exporterContext, length),
          await sender.Export(exporterContext, length),
        )
      },
    ),
    options,
  )
})

test('context sequence round-trips arbitrary message streams', async () => {
  const recipient = await suite.GenerateKeyPair()
  const messages = fc.array(fc.record({ plaintext: bytes, aad: metadata }), {
    minLength: 1,
    maxLength: 8,
  })

  await fc.assert(
    fc.asyncProperty(metadata, messages, async (info, values) => {
      const { encapsulatedSecret, ctx: sender } = await suite.SetupSender(recipient.publicKey, {
        info,
      })
      const receiver = await suite.SetupRecipient(recipient, encapsulatedSecret, {
        info,
      })

      for (const { plaintext, aad } of values) {
        assert.deepEqual(await receiver.Open(await sender.Seal(plaintext, aad), aad), plaintext)
      }
    }),
    options,
  )
})
