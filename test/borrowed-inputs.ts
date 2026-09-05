import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as HPKE from '../index.ts'

for (const useBuffer of [false, true]) {
  for (const multiShot of [false, true]) {
    test(`${multiShot ? 'context' : 'single-shot'} APIs pass ${useBuffer ? 'Buffer' : 'Uint8Array'} views to WebCrypto`, async (context) => {
      context.after(() => context.mock.restoreAll())
      const bytes = (length: number): Uint8Array =>
        useBuffer ? Buffer.alloc(length, 17) : new Uint8Array(length).fill(17)
      const plaintext = bytes(64).subarray(7, 23)
      const aad = bytes(32).subarray(3, 14)
      const suite = new HPKE.CipherSuite(
        HPKE.KEM_DHKEM_P256_HKDF_SHA256,
        HPKE.KDF_HKDF_SHA256,
        HPKE.AEAD_AES_128_GCM,
      )
      const recipient = await suite.GenerateKeyPair()
      const encrypt = context.mock.method(crypto.subtle, 'encrypt')
      const decrypt = context.mock.method(crypto.subtle, 'decrypt')

      const sender = multiShot ? await suite.SetupSender(recipient.publicKey) : undefined
      const sealed = sender
        ? {
            encapsulatedSecret: sender.encapsulatedSecret,
            ciphertext: await sender.ctx.Seal(plaintext, aad),
          }
        : await suite.Seal(recipient.publicKey, plaintext, { aad })

      assert.equal(encrypt.mock.callCount(), 1)
      assert.equal(encrypt.mock.calls[0]!.arguments[2], plaintext)
      assert.equal((encrypt.mock.calls[0]!.arguments[0] as AesGcmParams).additionalData, aad)

      const ciphertext = bytes(sealed.ciphertext.byteLength + 8).subarray(4, -4)
      ciphertext.set(sealed.ciphertext)
      const receiver = multiShot
        ? await suite.SetupRecipient(recipient, sealed.encapsulatedSecret)
        : undefined
      const opened = receiver
        ? await receiver.Open(ciphertext, aad)
        : await suite.Open(recipient, sealed.encapsulatedSecret, ciphertext, { aad })

      assert.deepEqual(opened, new Uint8Array(plaintext))
      assert.equal(decrypt.mock.callCount(), 1)
      assert.equal(decrypt.mock.calls[0]!.arguments[2], ciphertext)
      assert.equal((decrypt.mock.calls[0]!.arguments[0] as AesGcmParams).additionalData, aad)
    })
  }
}
