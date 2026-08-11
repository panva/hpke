// Type-level regression tests. Nothing here runs; `tsc` compiling this file is the assertion.
import * as HPKE from 'hpke'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

declare const bytes: Uint8Array
declare const customKEM: HPKE.KEMFactory<CustomKey>
declare const defaultKEM: HPKE.KEMFactory
declare const sender: HPKE.SenderContext
declare const recipient: HPKE.RecipientContext

interface CustomKey extends HPKE.Key {
  readonly custom: true
}

/* The package aliases the host CryptoKey instead of introducing a competing structural type. */
{
  const _isHostCryptoKey: Equals<HPKE.CryptoKey, CryptoKey> = true
  // @ts-expect-error `any` would accept this
  const _notAny: HPKE.CryptoKey = 'definitely not a key'
}

/* WebCrypto-backed KEMs preserve their concrete key type through CipherSuite. */
async function webCryptoKeys() {
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_P256_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_128_GCM,
  )
  const _suite: Equals<typeof suite, HPKE.CipherSuite<HPKE.CryptoKey>> = true
  const pair = await suite.GenerateKeyPair()
  const _pair: Equals<typeof pair, HPKE.KeyPair<HPKE.CryptoKey>> = true
  const _hostPair: CryptoKeyPair = pair
  const _publicKey: CryptoKey = pair.publicKey
  const _privateKey: CryptoKey = pair.privateKey

  await crypto.subtle.exportKey('raw', pair.publicKey)

  const derived = await suite.DeriveKeyPair(bytes)
  const _derived: Equals<typeof derived, HPKE.KeyPair<HPKE.CryptoKey>> = true

  const publicKey = await suite.DeserializePublicKey(bytes)
  const privateKey = await suite.DeserializePrivateKey(bytes)
  const _publicIsCryptoKey: Equals<typeof publicKey, HPKE.CryptoKey> = true
  const _privateIsCryptoKey: Equals<typeof privateKey, HPKE.CryptoKey> = true
}

/* Hybrid KEMs keep their non-WebCrypto key abstraction. */
async function hybridKeys() {
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_MLKEM768_X25519,
    HPKE.KDF_SHAKE256,
    HPKE.AEAD_AES_128_GCM,
  )
  const pair = await suite.GenerateKeyPair()
  const _key: HPKE.Key = pair.publicKey
  // @ts-expect-error HybridKey is not promised to be a WebCrypto CryptoKey
  pair.publicKey.usages
}

/* Consumer-supplied and default key representations both retain their inferred type. */
async function customKeys() {
  const customSuite = new HPKE.CipherSuite(customKEM, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
  const customPair = await customSuite.GenerateKeyPair()
  const _custom: Equals<typeof customPair.publicKey, Readonly<CustomKey>> = true

  const defaultSuite = new HPKE.CipherSuite(defaultKEM, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
  const defaultPair = await defaultSuite.GenerateKeyPair()
  const _default: Equals<typeof defaultPair.publicKey, Readonly<HPKE.Key>> = true
}

/* Context modes stay within the modes this implementation supports. */
{
  const _senderMode: Equals<typeof sender.mode, HPKE.Mode> = true
  const _recipientMode: Equals<typeof recipient.mode, HPKE.Mode> = true
}

/* Suite descriptors are exposed as readonly snapshots. */
{
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_P256_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_128_GCM,
  )
  // @ts-expect-error suite metadata is readonly
  suite.KEM.id = 0
  // @ts-expect-error suite metadata is readonly
  suite.KDF.stages = 1
  // @ts-expect-error suite metadata is readonly
  suite.AEAD.Nk = 0
}
