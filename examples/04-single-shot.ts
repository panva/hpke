import * as HPKE from '../index.ts'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Cipher suite components (agreed upon by both sender and recipient upfront)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Recipient: Generate a key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// Sender: Single-shot encryption (seal and send one message)
const plaintext = encoder.encode('Single encrypted message')

const { encapsulatedSecret, ciphertext } = await suite.Seal(recipientKeyPair.publicKey, plaintext)

// Sender → Recipient: Send enc, and ct

// Recipient: Single-shot decryption (open one message)
const decrypted = await suite.Open(recipientKeyPair, encapsulatedSecret, ciphertext)

console.log(decoder.decode(decrypted)) // "Single encrypted message"

// Single-shot mode is useful when:
// - Only one message needs to be sent
// - You don't need to maintain context state
// - You want simpler API for one-time encryption
