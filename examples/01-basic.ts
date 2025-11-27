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

// Recipient: Serialize public key for distribution
const recipientPublicKeySerialized = await suite.SerializePublicKey(recipientKeyPair.publicKey)

// Recipient → Sender: Distribute public key(s)

// Sender: Deserialize recipient's public key
const recipientPublicKey = await suite.DeserializePublicKey(recipientPublicKeySerialized)

// Sender: Setup sender context
const { encapsulatedSecret, ctx: senderCtx } = await suite.SetupSender(recipientPublicKey)

// Sender → Recipient: Send encapsulated secret (enc)

// Recipient: Setup recipient context using encapsulated secret
const recipientCtx = await suite.SetupRecipient(recipientKeyPair, encapsulatedSecret)

// Sender: Encrypt first message with AAD
const aad1 = encoder.encode('message-id-1')
const plaintext1 = encoder.encode('Hello from sender!')
const ciphertext1 = await senderCtx.Seal(plaintext1, aad1)

// Sender → Recipient: Send ciphertext1 and aad1

// Recipient: Decrypt first message
const decrypted1 = await recipientCtx.Open(ciphertext1, aad1)
console.log(decoder.decode(decrypted1)) // "Hello from sender!"

// Sender: Encrypt second message with AAD
const aad2 = encoder.encode('message-id-2')
const plaintext2 = encoder.encode('Second message')
const ciphertext2 = await senderCtx.Seal(plaintext2, aad2)

// Sender → Recipient: Send ciphertext2 and aad2

// Recipient: Decrypt second message
const decrypted2 = await recipientCtx.Open(ciphertext2, aad2)
console.log(decoder.decode(decrypted2)) // "Second message"
