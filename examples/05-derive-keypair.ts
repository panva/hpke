import * as HPKE from '../index.ts'

const encoder = new TextEncoder()

// Cipher suite components (agreed upon by both sender and recipient upfront)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Deterministically derive a key pair from input keying material
// WARNING: ikm must be cryptographically secure and NEVER reused elsewhere, particularly not with `DeriveKeyPair()` of a
// different KEM.
const ikm = crypto.getRandomValues(new Uint8Array(suite.KEM.Nsk))

// Recipient: Derive key pair from IKM (extractable for demonstration)
const recipientKeyPair = await suite.DeriveKeyPair(ikm, true)

// The same IKM will always produce the same key pair
const recipientKeyPair2 = await suite.DeriveKeyPair(ikm, true)

// Verify both derivations produce the same public key
const pk1 = await suite.SerializePublicKey(recipientKeyPair.publicKey)
const pk2 = await suite.SerializePublicKey(recipientKeyPair2.publicKey)

console.log(
  'Public keys match:',
  pk1.every((byte, i) => byte === pk2[i]),
) // true

// Sender: Setup sender context
const { encapsulatedKey, ctx: senderCtx } = await suite.SetupSender(recipientKeyPair.publicKey)

// Recipient: Setup recipient context
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulatedKey)

// Sender: Encrypt message
const aad = encoder.encode('metadata')
const plaintext = encoder.encode('Message encrypted with derived key pair')
const ciphertext = await senderCtx.Seal(plaintext, aad)

// Recipient decrypts the message
const decrypted = await recipientCtx.Open(ciphertext, aad)
console.log('Decrypted:', new TextDecoder().decode(decrypted))

// Use cases for DeriveKeyPair:
// - Deriving keys from passwords (with proper KDF like PBKDF2 first)
// - Hierarchical key derivation schemes
// - Deterministic key generation for testing
// - Key backup and recovery scenarios
