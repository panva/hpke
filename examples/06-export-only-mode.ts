import * as HPKE from '../index.ts'

const encoder = new TextEncoder()

// Cipher suite with EXPORT_ONLY AEAD (no encryption/decryption)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_EXPORT_ONLY,
)

// Recipient: Generate a key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// Sender: Setup sender context (no encryption capability)
const { encapsulatedKey, ctx: senderCtx } = await suite.SetupSender(recipientKeyPair.publicKey)

// Recipient: Setup recipient context (no decryption capability)
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulatedKey)

// Export-only mode only supports exporting secrets
const exporterContext = encoder.encode('derived-key-material')

// Both parties derive the same secret
const senderSecret = await senderCtx.Export(exporterContext, 32)
const recipientSecret = await recipientCtx.Export(exporterContext, 32)

console.log(
  'Secrets match:',
  senderSecret.every((byte, i) => byte === recipientSecret[i]),
) // true

// Use cases for Export-only mode:
// - Key agreement protocols that don't need AEAD
// - Deriving shared secrets for external encryption
// - Establishing session keys for other protocols
// - Reducing overhead when encryption is not needed
// - TLS-style key derivation without using TLS
