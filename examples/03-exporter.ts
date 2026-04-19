import * as HPKE from '../index.ts'

const encoder = new TextEncoder()

// Cipher suite components (agreed upon by both sender and recipient upfront)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Recipient: Generate a key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// Sender: Setup sender context
const { encapsulatedSecret, ctx: senderCtx } = await suite.SetupSender(recipientKeyPair.publicKey)

// Recipient: Setup recipient context
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulatedSecret)

// Both parties can export secrets using the same exporter context
const exporterContext1 = encoder.encode('encryption-key')
const exporterContext2 = encoder.encode('mac-key')

// Sender: Export secrets
const senderDerivedKey1 = await senderCtx.Export(exporterContext1, 32)
const senderDerivedKey2 = await senderCtx.Export(exporterContext2, 16)

// Recipient: Export the same secrets
const recipientDerivedKey1 = await recipientCtx.Export(exporterContext1, 32)
const recipientDerivedKey2 = await recipientCtx.Export(exporterContext2, 16)

// Verify both parties derived the same secrets
const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, i) => byte === b[i])

console.log(
  'Keys match:',
  equal(senderDerivedKey1, recipientDerivedKey1) && equal(senderDerivedKey2, recipientDerivedKey2),
) // true

// These derived secrets can be used for:
// - Additional encryption keys
// - MAC keys
// - Session identifiers
// - Any application-specific cryptographic material
console.log('Derived key 1 length:', senderDerivedKey1.length) // 32
console.log('Derived key 2 length:', senderDerivedKey2.length) // 16
