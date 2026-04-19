import * as HPKE from '../index.ts'

const encoder = new TextEncoder()

// Cipher suite components (agreed upon by both sender and recipient upfront)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_EXPORT_ONLY,
)

// Recipient: Generate a key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// Exporter context (agreed upon by both sender and recipient upfront)
const exporterContext = encoder.encode('derived-key-material')

// Sender: Single-shot secret export (setup sender context and export in one call)
const { encapsulatedSecret, exportedSecret: senderSecret } = await suite.SendExport(
  recipientKeyPair.publicKey,
  exporterContext,
  32,
)

// Sender → Recipient: Send enc

// Recipient: Single-shot secret export (setup recipient context and export in one call)
const recipientSecret = await suite.ReceiveExport(
  recipientKeyPair,
  encapsulatedSecret,
  exporterContext,
  32,
)

console.log(
  'Secrets match:',
  senderSecret.length === recipientSecret.length &&
    senderSecret.every((byte, i) => byte === recipientSecret[i]),
) // true

// Single-shot SendExport/ReceiveExport is useful when:
// - A single exported secret is needed (no multi-message context)
// - Pairing naturally with AEAD_EXPORT_ONLY for pure key agreement
// - Simpler API than managing a SenderContext/RecipientContext lifecycle
