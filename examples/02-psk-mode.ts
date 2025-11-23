import * as HPKE from '../index.ts'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Cipher suite components (agreed upon by both sender and recipient upfront)
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Pre-shared key and identifier (agreed upon by both sender and recipient upfront)
const psk = crypto.getRandomValues(new Uint8Array(32))
const pskId = encoder.encode('shared-key-id-2024')

// Recipient: Generate a key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// Recipient: Serialize public key for sending
const recipientPublicKeySerialized = await suite.SerializePublicKey(recipientKeyPair.publicKey)

// Recipient → Sender: Send serialized public key

// Sender: Deserialize recipient's public key
const recipientPublicKey = await suite.DeserializePublicKey(recipientPublicKeySerialized)

// Sender: Setup sender context with PSK mode
const { encapsulatedKey, ctx: senderCtx } = await suite.SetupSender(recipientPublicKey, {
  psk,
  pskId,
})

// Sender → Recipient: Send encapsulated key (enc)

// Recipient: Setup recipient context with PSK mode
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulatedKey, { psk, pskId })

// Sender: Encrypt message with AAD
const aad = encoder.encode('authenticated-data')
const plaintext = encoder.encode('Authenticated message using PSK mode')
const ciphertext = await senderCtx.Seal(plaintext, aad)

// Sender → Recipient: Send ciphertext and aad

// Recipient: Decrypt message
const decrypted = await recipientCtx.Open(ciphertext, aad)
console.log(decoder.decode(decrypted)) // "Authenticated message using PSK mode"

// Verify we're in PSK mode
console.log('Mode:', senderCtx.mode === HPKE.MODE_PSK ? 'PSK' : 'Base') // "Mode: PSK"
console.log('Mode:', recipientCtx.mode === HPKE.MODE_PSK ? 'PSK' : 'Base') // "Mode: PSK"
