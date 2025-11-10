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
const { encapsulated_key, ctx: senderCtx } = await suite.SetupSender(recipientKeyPair.publicKey)

// Recipient: Setup recipient context
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulated_key)

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
console.log(
  'Keys match:',
  senderDerivedKey1.every((byte, i) => byte === recipientDerivedKey1[i]) &&
    senderDerivedKey2.every((byte, i) => byte === recipientDerivedKey2[i]),
) // true

// These derived secrets can be used for:
// - Additional encryption keys
// - MAC keys
// - Session identifiers
// - Any application-specific cryptographic material
console.log('Derived key 1 length:', senderDerivedKey1.length) // 32
console.log('Derived key 2 length:', senderDerivedKey2.length) // 16
