/**
 * Hybrid Public Key Encryption (HPKE) implementation for JavaScript runtimes.
 *
 * Implements an authenticated encryption encapsulation format that combines a semi-static
 * asymmetric key exchange with a symmetric cipher. This was originally defined in an Informational
 * document on the IRTF stream as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and is now
 * being republished as a Standards Track document of the IETF as
 * [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02).
 *
 * HPKE provides a variant of public key encryption for arbitrary-sized plaintexts using a recipient
 * public key.
 *
 * @module hpke
 * @example
 *
 * Getting started with {@link CipherSuite}
 *
 * ```ts
 * import * as HPKE from '@panva/hpke'
 *
 * // 1. Choose a cipher suite
 * const suite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   HPKE.KDF_HKDF_SHA256,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 *
 * // 2. Generate recipient key pair
 * const recipient = await suite.GenerateKeyPair()
 *
 * // 3. Encrypt a message
 * const plaintext = new TextEncoder().encode('Hello, World!')
 * const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext)
 *
 * // 4. Decrypt the message
 * const decrypted = await suite.Open(recipient.privateKey, encapsulatedSecret, ciphertext)
 * console.log(new TextDecoder().decode(decrypted)) // "Hello, World!"
 * ```
 */

// ============================================================================
// HPKE Context Classes - Sender and Recipient Contexts
// ============================================================================

function ComputeNonce(base_nonce: Uint8Array, seq: number, Nn: number): Uint8Array {
  const seq_bytes = I2OSP(seq, Nn)
  return xor(base_nonce, seq_bytes)
}

function IncrementSeq(seq: number): number {
  // seq is guaranteed to be a safe integer due to:
  // 1. Initial value is 0
  // 2. This function throws at MAX_SAFE_INTEGER
  if (seq >= Number.MAX_SAFE_INTEGER) {
    throw new MessageLimitReachedError('Sequence number overflow')
  }
  return ++seq
}

async function ContextExport(
  suite: Triple,
  exporterSecret: Uint8Array,
  exporterContext: Uint8Array,
  L: number,
) {
  const stages = KDFStages(suite.KDF)
  if (!(exporterContext instanceof Uint8Array)) {
    throw new TypeError('"exporterContext" must be a Uint8Array')
  }
  if (!Number.isInteger(L) || L <= 0 || L > 0xffff) {
    throw new TypeError('"L" must be a positive integer not exceeding 65535')
  }
  const Export = stages === 1 ? ExportOneStage : ExportTwoStage
  return await Export(suite.KDF, suite.id, exporterSecret, exporterContext, L)
}

class Mutex {
  #locked: Promise<void> = Promise.resolve()

  async lock(): Promise<() => void> {
    let releaseLock!: () => void
    const nextLock = new Promise<void>((resolve) => {
      releaseLock = resolve
    })
    const previousLock = this.#locked
    this.#locked = nextLock
    await previousLock
    return releaseLock
  }
}

/**
 * Context for encrypting multiple messages and exporting secrets on the sender side.
 *
 * `SenderContext` instance is obtained from {@link CipherSuite.SetupSender}.
 *
 * This context maintains an internal sequence number that increments with each {@link Seal}
 * operation, ensuring nonce uniqueness for the underlying AEAD algorithm.
 *
 * @example
 *
 * ```ts
 * let suite!: HPKE.CipherSuite
 * let publicKey!: HPKE.Key // recipient's public key
 *
 * const { encapsulatedSecret, ctx } = await suite.SetupSender(publicKey)
 * ```
 *
 * @group Core
 */
class SenderContext {
  #suite: Triple
  #key: Uint8Array
  #base_nonce: Uint8Array
  #exporter_secret: Uint8Array
  #mode: number
  #seq: number = 0
  #mutex?: Mutex

  constructor(
    suite: Triple,
    mode: number,
    key: Uint8Array,
    base_nonce: Uint8Array,
    exporter_secret: Uint8Array,
  ) {
    this.#suite = suite
    this.#mode = mode
    this.#key = key
    this.#base_nonce = base_nonce
    this.#exporter_secret = exporter_secret
  }

  /** @returns The mode (0x00 = Base, 0x01 = PSK) for this context. */
  get mode(): number {
    return this.#mode
  }

  /**
   * @returns The sequence number for this context's next {@link Seal}, initially zero, increments
   *   automatically with each successful {@link Seal}. The sequence number provides AEAD nonce
   *   uniqueness.
   */
  get seq(): number {
    return this.#seq
  }

  /**
   * Encrypts plaintext with additional authenticated data. Each successful call automatically
   * increments the sequence number to ensure nonce uniqueness.
   *
   * @example
   *
   * ```ts
   * let ctx!: HPKE.SenderContext
   *
   * // Encrypt multiple messages with the same context
   * const aad1: Uint8Array = new TextEncoder().encode('message 1 aad')
   * const pt1: Uint8Array = new TextEncoder().encode('First message')
   * const ct1: Uint8Array = await ctx.Seal(pt1, aad1)
   *
   * const aad2: Uint8Array = new TextEncoder().encode('message 2 aad')
   * const pt2: Uint8Array = new TextEncoder().encode('Second message')
   * const ct2: Uint8Array = await ctx.Seal(pt2, aad2)
   * ```
   *
   * @param plaintext - Plaintext to encrypt
   * @param aad - Additional authenticated data
   *
   * @returns A Promise that resolves to the ciphertext. The ciphertext is {@link Nt} bytes longer
   *   than the plaintext.
   */
  async Seal(plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('"plaintext" must be an Uint8Array')
    }
    aad ??= new Uint8Array()
    if (!(aad instanceof Uint8Array)) {
      throw new TypeError('"aad" must be an Uint8Array')
    }
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }

    this.#mutex ??= new Mutex()
    const release = await this.#mutex.lock()
    let ct: Uint8Array
    try {
      ct = await this.#suite.AEAD.Seal(
        this.#key,
        ComputeNonce(this.#base_nonce, this.#seq, this.#suite.AEAD.Nn),
        aad,
        plaintext,
      )
      this.#seq = IncrementSeq(this.#seq)
      return ct
    } finally {
      release()
    }
  }

  /**
   * Exports a secret using a variable-length pseudorandom function (PRF).
   *
   * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
   *
   * @example
   *
   * ```ts
   * let ctx!: HPKE.SenderContext
   *
   * // Export a 32-byte secret
   * const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
   * const exportedSecret: Uint8Array = await ctx.Export(exporterContext, 32)
   *
   * // The recipient can derive the same secret using the same exporterContext
   * ```
   *
   * @param exporterContext - Context for domain separation
   * @param length - Desired length of exported secret in bytes
   *
   * @returns A Promise that resolves to the exported secret.
   */
  async Export(exporterContext: Uint8Array, length: number): Promise<Uint8Array> {
    return await ContextExport(this.#suite, this.#exporter_secret, exporterContext, length)
  }

  /**
   * @returns The length in bytes of an authentication tag for the AEAD algorithm used by this
   *   context.
   */
  get Nt(): number {
    return this.#suite.AEAD.Nt
  }
}
export type { SenderContext }

/**
 * Context for decrypting multiple messages and exporting secrets on the recipient side.
 *
 * `RecipientContext` instance is obtained from {@link CipherSuite.SetupRecipient}.
 *
 * @example
 *
 * ```ts
 * let suite!: HPKE.CipherSuite
 * let privateKey!: HPKE.Key | HPKE.KeyPair
 *
 * // ... receive encapsulatedSecret from sender
 * let encapsulatedSecret!: Uint8Array
 *
 * const ctx: HPKE.RecipientContext = await suite.SetupRecipient(privateKey, encapsulatedSecret)
 * ```
 *
 * @group Core
 */
class RecipientContext {
  #suite: Triple
  #key: Uint8Array
  #base_nonce: Uint8Array
  #exporter_secret: Uint8Array
  #mode: number
  #seq: number = 0
  #mutex?: Mutex

  constructor(
    suite: Triple,
    mode: number,
    key: Uint8Array,
    base_nonce: Uint8Array,
    exporter_secret: Uint8Array,
  ) {
    this.#suite = suite
    this.#mode = mode
    this.#key = key
    this.#base_nonce = base_nonce
    this.#exporter_secret = exporter_secret
  }

  /** @returns The mode (0x00 = Base, 0x01 = PSK) for this context. */
  get mode(): number {
    return this.#mode
  }

  /**
   * @returns The sequence number for this context's next {@link Open}, initially zero, increments
   *   automatically with each successful {@link Open}. The sequence number provides AEAD nonce
   *   uniqueness.
   */
  get seq(): number {
    return this.#seq
  }

  // /**
  //  * Sets the sequence number for this context's next {@link Open}. The sequence number provides AEAD
  //  * nonce uniqueness.
  //  *
  //  * This API is intended for protocols that may experience packet loss and need to decrypt arriving
  //  * packets out of order. The sequence number determines the nonce that will be used next.
  //  *
  //  * Control over the sequence number is only given to the recipient since reuse of the same nonce
  //  * by a sender could lead to loss of confidentiality and integrity.
  //  *
  //  * @param seq - The sequence number to use for the next {@link Open}.
  //  */
  // set seq(seq: number) {
  //   if (!Number.isSafeInteger(seq) || seq < 0) {
  //     throw new TypeError('seq must be a non-negative safe integer')
  //   }

  //   this.#seq = seq
  // }

  /**
   * Decrypts ciphertext with additional authenticated data.
   *
   * Applications must ensure that ciphertexts are presented to `Open` in the exact order they were
   * produced by the sender.
   *
   * @example
   *
   * ```ts
   * let ctx!: HPKE.RecipientContext
   *
   * // Decrypt multiple messages with the same context
   * let aad1!: Uint8Array | undefined
   * let ct1!: Uint8Array
   * const pt1: Uint8Array = await ctx.Open(ct1, aad1)
   *
   * let aad2!: Uint8Array | undefined
   * let ct2!: Uint8Array
   * const pt2: Uint8Array = await ctx.Open(ct2, aad2)
   * ```
   *
   * @param ciphertext - Ciphertext to decrypt
   * @param aad - Additional authenticated data
   *
   * @returns A Promise that resolves to the decrypted plaintext.
   */
  async Open(ciphertext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    if (!(ciphertext instanceof Uint8Array)) {
      throw new TypeError('"ciphertext" must be an Uint8Array')
    }

    aad ??= new Uint8Array()
    if (!(aad instanceof Uint8Array)) {
      throw new TypeError('"aad" must be an Uint8Array')
    }

    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }

    this.#mutex ??= new Mutex()
    const release = await this.#mutex.lock()
    try {
      let pt: Uint8Array
      try {
        pt = await this.#suite.AEAD.Open(
          this.#key,
          ComputeNonce(this.#base_nonce, this.#seq, this.#suite.AEAD.Nn),
          aad,
          ciphertext,
        )
      } catch (cause) {
        if (cause instanceof MessageLimitReachedError || cause instanceof NotSupportedError) {
          throw cause
        }

        throw new OpenError('AEAD decryption failed', { cause })
      }
      this.#seq = IncrementSeq(this.#seq)
      return pt
    } finally {
      release()
    }
  }

  /**
   * Exports a secret using a variable-length pseudorandom function (PRF).
   *
   * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
   *
   * @example
   *
   * ```ts
   * let ctx!: HPKE.RecipientContext
   *
   * // Export a 32-byte secret
   * const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
   * const exported: Uint8Array = await ctx.Export(exporterContext, 32)
   *
   * // The sender can derive the same secret using the same exporterContext
   * ```
   *
   * @param exporterContext - Context for domain separation
   * @param length - Desired length of exported secret in bytes
   *
   * @returns A Promise that resolves to the exported secret.
   */
  async Export(exporterContext: Uint8Array, length: number): Promise<Uint8Array> {
    return await ContextExport(this.#suite, this.#exporter_secret, exporterContext, length)
  }
}
export type { RecipientContext }

// ============================================================================
// Main CipherSuite Class
// ============================================================================

const validate = <T extends { type: string }>(factory: () => T, type: string): T => {
  try {
    const result = factory()
    if (result.type !== type) {
      throw new Error(`Invalid "${type}" return discriminator`)
    }
    return result
  } catch (cause) {
    throw new TypeError(`Invalid "${type}"`, { cause })
  }
}

/**
 * Hybrid Public Key Encryption (HPKE) suite combining a KEM, KDF, and AEAD.
 *
 * Implements an authenticated encryption encapsulation format that combines a semi-static
 * asymmetric key exchange with a symmetric cipher. This was originally defined in an Informational
 * document on the IRTF stream as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and is now
 * being republished as a Standards Track document of the IETF as
 * [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02).
 *
 * HPKE provides a variant of public key encryption for arbitrary-sized plaintexts using a recipient
 * public key. It supports two modes:
 *
 * - Base mode: Encryption to a public key without sender authentication
 * - PSK mode: Encryption with pre-shared key authentication
 *
 * The cipher suite consists of:
 *
 * - KEM: Key Encapsulation Mechanism for establishing shared secrets
 * - KDF: Key Derivation Function for deriving symmetric keys
 * - AEAD: Authenticated Encryption with Additional Data for encryption
 *
 * @group Core
 */
export class CipherSuite {
  #suite: Triple

  /**
   * Creates a new HPKE cipher suite by combining a Key Encapsulation Mechanism (KEM), Key
   * Derivation Function (KDF), and an Authenticated Encryption with Associated Data (AEAD)
   * algorithm.
   *
   * A cipher suite defines the complete cryptographic configuration for HPKE operations. The choice
   * of algorithms affects security properties, performance, and compatibility across different
   * platforms and runtimes.
   *
   * @example
   *
   * Traditional algorithms
   *
   * ```ts
   * import * as HPKE from '@panva/hpke'
   *
   * const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
   *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
   *   HPKE.KDF_HKDF_SHA256,
   *   HPKE.AEAD_AES_128_GCM,
   * )
   * ```
   *
   * @example
   *
   * Hybrid post-quantum/traditional (PQ/T) KEM
   *
   * ```ts
   * import * as HPKE from '@panva/hpke'
   *
   * const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
   *   HPKE.KEM_MLKEM768_X25519,
   *   HPKE.KDF_SHAKE256,
   *   HPKE.AEAD_ChaCha20Poly1305,
   * )
   * ```
   *
   * @example
   *
   * Post-quantum (PQ) KEM
   *
   * ```ts
   * import * as HPKE from '@panva/hpke'
   *
   * const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
   *   HPKE.KEM_ML_KEM_768,
   *   HPKE.KDF_SHAKE256,
   *   HPKE.AEAD_ChaCha20Poly1305,
   * )
   * ```
   *
   * @param KEM - KEM implementation factory. Must return an object conforming to the {@link KEM}
   *   interface.
   * @param KDF - KDF implementation factory. Must return an object conforming to the {@link KDF}
   *   interface.
   * @param AEAD - AEAD implementation factory. Must return an object conforming to the {@link AEAD}
   *   interface.
   * @see {@link KEMFactory Available KEMs}
   * @see {@link KDFFactory Available KDFs}
   * @see {@link AEADFactory Available AEADs}
   */
  constructor(KEM: KEMFactory, KDF: KDFFactory, AEAD: AEADFactory) {
    const kem = validate(KEM, 'KEM')
    const kdf = validate(KDF, 'KDF')
    const aead = validate(AEAD, 'AEAD')

    this.#suite = {
      KEM: kem,
      KDF: kdf,
      AEAD: aead,
      id: concat(encode('HPKE'), I2OSP(kem.id, 2), I2OSP(kdf.id, 2), I2OSP(aead.id, 2)),
    }
  }

  /**
   * Provides read-only access to this suite's KEM identifier, name, and other attributes.
   *
   * @returns An object with this suite's Key Encapsulation Mechanism (KEM) properties.
   */
  get KEM(): {
    /** The identifier of this suite's KEM */
    id: number
    /** The name of this suite's KEM */
    name: string
    /** The length in bytes of this suite's KEM produced shared secret */
    Nsecret: number
    /** The length in bytes of this suite's KEM produced encapsulated secret */
    Nenc: number
    /** The length in bytes of this suite's KEM public key */
    Npk: number
    /** The length in bytes of this suite's KEM private key */
    Nsk: number
  } {
    return {
      id: this.#suite.KEM.id,
      name: this.#suite.KEM.name,
      Nsecret: this.#suite.KEM.Nsecret,
      Nenc: this.#suite.KEM.Nenc,
      Npk: this.#suite.KEM.Npk,
      Nsk: this.#suite.KEM.Nsk,
    }
  }

  /**
   * Provides read-only access to this suite's KDF identifier, name, and other attributes.
   *
   * @returns An object with this suite's Key Derivation Function (KDF) properties.
   */
  get KDF(): {
    /** The identifier of this suite's KDF */
    id: number
    /** The name of this suite's KDF */
    name: string
    /**
     * When 1, this suite's KDF is a one-stage (Derive) KDF.
     *
     * When 2, this suite's KDF is a two-stage (Extract and Expand) KDF.
     */
    stages: 1 | 2
    /**
     * For one-stage KDF: The security strength of this suite's KDF, in bytes.
     *
     * For two-stage KDF: The output size of this suite's KDF Extract() function in bytes.
     */
    Nh: number
  } {
    return {
      id: this.#suite.KDF.id,
      name: this.#suite.KDF.name,
      stages: this.#suite.KDF.stages,
      Nh: this.#suite.KDF.Nh,
    }
  }

  /**
   * Provides read-only access to this suite's AEAD identifier, name, and other attributes.
   *
   * @returns An object with this suite's Authenticated Encryption with Associated Data (AEAD)
   *   cipher properties.
   */
  get AEAD(): {
    /** The identifier of this suite's AEAD */
    id: number
    /** The name of this suite's AEAD */
    name: string
    /** The length in bytes of a key for this suite's AEAD */
    Nk: number
    /** The length in bytes of a nonce for this suite's AEAD */
    Nn: number
    /** The length in bytes of an authentication tag for this suite's AEAD */
    Nt: number
  } {
    return {
      id: this.#suite.AEAD.id,
      name: this.#suite.AEAD.name,
      Nk: this.#suite.AEAD.Nk,
      Nn: this.#suite.AEAD.Nn,
      Nt: this.#suite.AEAD.Nt,
    }
  }

  /**
   * Generates a random key pair for this CipherSuite. By default, private keys are generated as
   * non-extractable (their value cannot be exported).
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * const keyPair: HPKE.KeyPair = await suite.GenerateKeyPair()
   * ```
   *
   * @param extractable - Whether the generated key pair's private key should be extractable (e.g.
   *   by {@link SerializePrivateKey}) (default: false)
   *
   * @returns A Promise that resolves to a generated key pair.
   */
  async GenerateKeyPair(extractable?: boolean): Promise<KeyPair> {
    extractable ??= false
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }
    return await this.#suite.KEM.GenerateKeyPair(extractable)
  }

  /**
   * Deterministically derives a key pair for this CipherSuite from input keying material. By
   * default, private keys are derived as non-extractable (their value cannot be exported).
   *
   * An `ikm` input MUST NOT be reused elsewhere, particularly not with `DeriveKeyPair()` of a
   * different KEM.
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let ikm!: Uint8Array // ... previously serialized ikm of at least suite.KEM.Nsk length
   * const keyPair: HPKE.KeyPair = await suite.DeriveKeyPair(ikm)
   * ```
   *
   * @param ikm - Input keying material (must be at least {@link CipherSuite.KEM Nsk} bytes)
   * @param extractable - Whether the derived key pair's private key should be extractable (e.g. by
   *   {@link SerializePrivateKey}) (default: false)
   *
   * @returns A Promise that resolves to the derived key pair.
   */
  async DeriveKeyPair(ikm: Uint8Array, extractable?: boolean): Promise<KeyPair> {
    extractable ??= false
    if (!(ikm instanceof Uint8Array)) {
      throw new TypeError('"ikm" must be an Uint8Array')
    }
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }
    if (ikm.byteLength < this.KEM.Nsk) {
      throw new DeriveKeyPairError('Insufficient "ikm" length')
    }
    try {
      return await this.#suite.KEM.DeriveKeyPair(ikm, extractable)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeriveKeyPairError('Key derivation failed', { cause })
    }
  }

  /**
   * Serializes an extractable private key to bytes.
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let privateKey!: HPKE.Key
   * const serialized: Uint8Array = await suite.SerializePrivateKey(privateKey)
   * ```
   *
   * @param privateKey - Private key to serialize
   *
   * @returns A Promise that resolves to the serialized private key.
   */
  async SerializePrivateKey(privateKey: Key): Promise<Uint8Array> {
    isKey(privateKey, 'private', true)

    return await this.#suite.KEM.SerializePrivateKey(privateKey)
  }

  /**
   * Serializes a public key to bytes.
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let publicKey!: HPKE.Key
   * const serialized: Uint8Array = await suite.SerializePublicKey(publicKey)
   * ```
   *
   * @param publicKey - Public key to serialize
   *
   * @returns A Promise that resolves to the serialized public key.
   */
  async SerializePublicKey(publicKey: Key): Promise<Uint8Array> {
    isKey(publicKey, 'public', true)

    return await this.#suite.KEM.SerializePublicKey(publicKey)
  }

  /**
   * Deserializes a private key from bytes. By default, private keys are deserialized as
   * non-extractable (their value cannot be exported).
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let serialized!: Uint8Array // ... previously serialized key of suite.KEM.Nsk length
   * const privateKey: HPKE.Key = await suite.DeserializePrivateKey(serialized)
   * ```
   *
   * @param privateKey - Serialized private key
   * @param extractable - Whether the deserialized private key should be extractable (e.g. by
   *   {@link SerializePrivateKey}) (default: false)
   *
   * @returns A Promise that resolves to the deserialized private key.
   */
  async DeserializePrivateKey(privateKey: Uint8Array, extractable?: boolean): Promise<Key> {
    extractable ??= false
    if (!(privateKey instanceof Uint8Array)) {
      throw new TypeError('"privateKey" must be an Uint8Array')
    }
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }

    try {
      if (privateKey.byteLength !== this.KEM.Nsk) {
        throw new Error('Invalid "privateKey" length')
      }
      return await this.#suite.KEM.DeserializePrivateKey(privateKey, extractable)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Private key deserialization failed', { cause })
    }
  }

  /**
   * Deserializes a public key from bytes. Public keys are always deserialized as extractable (their
   * value can be exported, e.g. by {@link SerializePublicKey}).
   *
   * @category Key Management
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let serialized!: Uint8Array // ... previously serialized key of suite.KEM.Npk length
   * const publicKey: HPKE.Key = await suite.DeserializePublicKey(serialized)
   * ```
   *
   * @param publicKey - Serialized public key
   *
   * @returns A Promise that resolves to the deserialized public key.
   */
  async DeserializePublicKey(publicKey: Uint8Array): Promise<Key> {
    if (!(publicKey instanceof Uint8Array)) {
      throw new TypeError('"publicKey" must be an Uint8Array')
    }

    try {
      if (publicKey.byteLength !== this.KEM.Npk) {
        throw new Error('Invalid "publicKey" length')
      }
      return await this.#suite.KEM.DeserializePublicKey(publicKey)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Public key deserialization failed', { cause })
    }
  }

  #validateEncLength(enc: Uint8Array) {
    if (enc.byteLength !== this.KEM.Nenc) {
      throw new DecapError('Invalid encapsulated secret length')
    }
  }

  /**
   * Single-shot API for encrypting a single message. It combines context setup and encryption in
   * one call.
   *
   * Mode selection:
   *
   * - If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
   * - If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)
   *
   * @category Single-Shot APIs
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let publicKey!: HPKE.Key // recipient's public key
   *
   * const plaintext: Uint8Array = new TextEncoder().encode('Hello, World!')
   *
   * const { encapsulatedSecret, ciphertext } = await suite.Seal(publicKey, plaintext)
   * ```
   *
   * @param publicKey - Recipient's public key
   * @param plaintext - Plaintext to encrypt
   * @param options - Options
   * @param options.aad - Additional authenticated data passed to the AEAD
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK modes)
   * @param options.pskId - Pre-shared key identifier (for PSK modes)
   *
   * @returns A Promise that resolves to an object containing the encapsulated secret and
   *   ciphertext. The ciphertext is {@link CipherSuite.AEAD Nt} bytes longer than the plaintext. The
   *   encapsulated secret is {@link CipherSuite.KEM Nenc} bytes.
   */
  async Seal(
    publicKey: Key,
    plaintext: Uint8Array,
    options?: { aad?: Uint8Array; info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<{ encapsulatedSecret: Uint8Array; ciphertext: Uint8Array }> {
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }
    const { encapsulatedSecret, ctx } = await this.SetupSender(publicKey, options)
    const ciphertext = await ctx.Seal(plaintext, options?.aad)
    return { encapsulatedSecret, ciphertext }
  }

  /**
   * Single-shot API for decrypting a single message.
   *
   * It combines context setup and decryption in one call.
   *
   * Mode selection:
   *
   * - If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
   * - If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)
   *
   * @category Single-Shot APIs
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let privateKey!: HPKE.Key | HPKE.KeyPair
   *
   * // ... receive encapsulatedSecret, ciphertext from sender
   * let encapsulatedSecret!: Uint8Array
   * let ciphertext!: Uint8Array
   *
   * const plaintext: Uint8Array = await suite.Open(privateKey, encapsulatedSecret, ciphertext)
   * ```
   *
   * @param privateKey - Recipient's private key or key pair
   * @param encapsulatedSecret - Encapsulated secret from the sender
   * @param ciphertext - Ciphertext to decrypt
   * @param options - Options
   * @param options.aad - Additional authenticated data
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK mode)
   * @param options.pskId - Pre-shared key identifier (for PSK mode)
   *
   * @returns A Promise that resolves to the decrypted plaintext.
   */
  async Open(
    privateKey: Key | KeyPair,
    encapsulatedSecret: Uint8Array,
    ciphertext: Uint8Array,
    options?: { aad?: Uint8Array; info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<Uint8Array> {
    this.#validateEncLength(encapsulatedSecret)
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }
    const ctx = await this.SetupRecipient(privateKey, encapsulatedSecret, options)
    return await ctx.Open(ciphertext, options?.aad)
  }

  /**
   * Single-shot API for deriving a secret known only to sender and recipient.
   *
   * It combines context setup and secret export in one call.
   *
   * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
   *
   * @category Single-Shot APIs
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let publicKey!: HPKE.Key // recipient's public key
   *
   * const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
   *
   * const { encapsulatedSecret, exportedSecret } = await suite.SendExport(
   *   publicKey,
   *   exporterContext,
   *   32,
   * )
   * ```
   *
   * @param publicKey - Recipient's public key
   * @param exporterContext - Context of the export operation
   * @param length - Desired length of exported secret in bytes
   * @param options - Options
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK modes)
   * @param options.pskId - Pre-shared key identifier (for PSK modes)
   *
   * @returns A Promise that resolves to an object containing the encapsulated secret and the
   *   exported secret.
   */
  async SendExport(
    publicKey: Key,
    exporterContext: Uint8Array,
    length: number,
    options?: { info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<{ encapsulatedSecret: Uint8Array; exportedSecret: Uint8Array }> {
    const { encapsulatedSecret, ctx } = await this.SetupSender(publicKey, options)
    const exportedSecret = await ctx.Export(exporterContext, length)
    return { encapsulatedSecret, exportedSecret }
  }

  /**
   * Single-shot API for receiving an exported secret.
   *
   * It combines context setup and secret export in one call.
   *
   * @category Single-Shot APIs
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let privateKey!: HPKE.Key | HPKE.KeyPair
   *
   * const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
   *
   * // ... receive encapsulatedSecret from sender
   * let encapsulatedSecret!: Uint8Array
   *
   * const exported: Uint8Array = await suite.ReceiveExport(
   *   privateKey,
   *   encapsulatedSecret,
   *   exporterContext,
   *   32,
   * )
   * ```
   *
   * @param privateKey - Recipient's private key or key pair
   * @param encapsulatedSecret - Encapsulated secret from the sender
   * @param exporterContext - Context of the export operation
   * @param length - Desired length of exported secret in bytes
   * @param options - Options
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK mode)
   * @param options.pskId - Pre-shared key identifier (for PSK mode)
   *
   * @returns A Promise that resolves to the exported secret.
   */
  async ReceiveExport(
    privateKey: Key | KeyPair,
    encapsulatedSecret: Uint8Array,
    exporterContext: Uint8Array,
    length: number,
    options?: { info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<Uint8Array> {
    this.#validateEncLength(encapsulatedSecret)
    const ctx = await this.SetupRecipient(privateKey, encapsulatedSecret, options)
    return await ctx.Export(exporterContext, length)
  }

  /**
   * Establishes a sender encryption context.
   *
   * Creates a context that can be used to encrypt multiple messages to the same recipient,
   * amortizing the cost of the public key operations.
   *
   * Mode selection:
   *
   * - If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
   * - If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)
   *
   * The returned context maintains a sequence number that increments with each encryption, ensuring
   * nonce uniqueness.
   *
   * @category Encryption Context
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let publicKey!: HPKE.Key // recipient's public key
   *
   * const { encapsulatedSecret, ctx } = await suite.SetupSender(publicKey)
   *
   * // Encrypt multiple messages with the same context
   * const aad1: Uint8Array = new TextEncoder().encode('message 1 aad')
   * const pt1: Uint8Array = new TextEncoder().encode('First message')
   * const ct1: Uint8Array = await ctx.Seal(pt1, aad1)
   *
   * const aad2: Uint8Array = new TextEncoder().encode('message 2 aad')
   * const pt2: Uint8Array = new TextEncoder().encode('Second message')
   * const ct2: Uint8Array = await ctx.Seal(pt2, aad2)
   * ```
   *
   * @param publicKey - Recipient's public key
   * @param options - Options
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK modes)
   * @param options.pskId - Pre-shared key identifier (for PSK modes)
   *
   * @returns A Promise that resolves to an object containing the encapsulated secret and the sender
   *   context (`ctx`). The encapsulated secret is {@link CipherSuite.KEM Nenc} bytes.
   */
  async SetupSender(
    publicKey: Key,
    options?: { info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<{ encapsulatedSecret: Uint8Array; ctx: SenderContext }> {
    isKey(publicKey, 'public')

    let shared_secret: Uint8Array
    let enc: Uint8Array
    try {
      const result = await this.#suite.KEM.Encap(publicKey)
      shared_secret = result.shared_secret
      enc = result.enc
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new EncapError('Encapsulation failed', { cause })
    }

    const mode = options?.psk?.byteLength ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.pskId,
    )

    const ctx = new SenderContext(this.#suite, mode, key, base_nonce, exporter_secret)
    return { encapsulatedSecret: enc, ctx }
  }

  /**
   * Establishes a recipient decryption context.
   *
   * Creates a context that can be used to decrypt multiple messages from the same sender.
   *
   * Mode selection:
   *
   * - If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
   * - If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)
   *
   * @category Encryption Context
   * @example
   *
   * ```ts
   * let suite!: HPKE.CipherSuite
   * let privateKey!: HPKE.Key | HPKE.KeyPair
   *
   * // ... receive encapsulatedSecret from sender
   * let encapsulatedSecret!: Uint8Array
   *
   * const ctx: HPKE.RecipientContext = await suite.SetupRecipient(
   *   privateKey,
   *   encapsulatedSecret,
   * )
   *
   * // ... receive messages from sender
   *
   * let aad1!: Uint8Array | undefined
   * let ct1!: Uint8Array
   *
   * const pt1: Uint8Array = await ctx.Open(ct1, aad1)
   *
   * let aad2!: Uint8Array | undefined
   * let ct2!: Uint8Array
   *
   * const pt2: Uint8Array = await ctx.Open(ct2, aad2)
   * ```
   *
   * @param privateKey - Recipient's private key or key pair
   * @param encapsulatedSecret - Encapsulated secret from the sender
   * @param options - Options
   * @param options.info - Application-supplied information
   * @param options.psk - Pre-shared key (for PSK mode)
   * @param options.pskId - Pre-shared key identifier (for PSK mode)
   *
   * @returns A Promise that resolves to the recipient context.
   */
  async SetupRecipient(
    privateKey: Key | KeyPair,
    encapsulatedSecret: Uint8Array,
    options?: { info?: Uint8Array; psk?: Uint8Array; pskId?: Uint8Array },
  ): Promise<RecipientContext> {
    const { skR, pkR } = this.#extractRecipientKeys(privateKey)
    this.#validateEncLength(encapsulatedSecret)

    let shared_secret: Uint8Array
    try {
      shared_secret = await this.#suite.KEM.Decap(encapsulatedSecret, skR, pkR)
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DecapError('Decapsulation failed', { cause })
    }

    const mode = options?.psk?.byteLength ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.pskId,
    )

    return new RecipientContext(this.#suite, mode, key, base_nonce, exporter_secret)
  }

  #extractRecipientKeys(skR: Key | KeyPair): { skR: Key; pkR: Key | undefined } {
    if (isKeyPair(skR)) {
      return { skR: skR.privateKey, pkR: skR.publicKey }
    }

    isKey(skR, 'private')
    return { skR, pkR: undefined }
  }
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Error thrown when input validation fails.
 *
 * @ignore
 * @group Errors
 */
export class ValidationError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'ValidationError'
    // @ts-ignore
    Error.captureStackTrace?.(this, ValidationError)
  }
}

/**
 * Error thrown when key deserialization fails.
 *
 * @ignore
 * @group Errors
 */
export class DeserializeError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'DeserializeError'
    // @ts-ignore
    Error.captureStackTrace?.(this, DeserializeError)
  }
}

/**
 * Error thrown when encapsulation operation fails.
 *
 * @ignore
 * @group Errors
 */
export class EncapError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'EncapError'
    // @ts-ignore
    Error.captureStackTrace?.(this, EncapError)
  }
}

/**
 * Error thrown when decapsulation operation fails.
 *
 * @ignore
 * @group Errors
 */
export class DecapError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'DecapError'
    // @ts-ignore
    Error.captureStackTrace?.(this, DecapError)
  }
}

/**
 * Error thrown when AEAD decryption (open) operation fails.
 *
 * @ignore
 * @group Errors
 */
export class OpenError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'OpenError'
    // @ts-ignore
    Error.captureStackTrace?.(this, OpenError)
  }
}

/**
 * Error thrown when the message sequence number limit is reached.
 *
 * @ignore
 * @group Errors
 */
export class MessageLimitReachedError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'MessageLimitReachedError'
    // @ts-ignore
    Error.captureStackTrace?.(this, MessageLimitReachedError)
  }
}

/**
 * Error thrown when key pair derivation fails.
 *
 * @ignore
 * @group Errors
 */
export class DeriveKeyPairError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'DeriveKeyPairError'
    // @ts-ignore
    Error.captureStackTrace?.(this, DeriveKeyPairError)
  }
}

/**
 * Error thrown when the runtime doesn't support an algorithm.
 *
 * @ignore
 * @group Errors
 */
export class NotSupportedError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'NotSupportedError'
    // @ts-ignore
    Error.captureStackTrace?.(this, NotSupportedError)
  }
}

// ============================================================================
// Type Definitions and Interfaces
// ============================================================================

interface Triple {
  readonly id: Uint8Array
  readonly KEM: Readonly<KEM>
  readonly KDF: Readonly<KDF>
  readonly AEAD: Readonly<AEAD>
}

/** Mode identifier for Base mode */
export const MODE_BASE = 0x00

/** Mode identifier for PSK mode */
export const MODE_PSK = 0x01

/**
 * Factory function that returns a KEM implementation.
 *
 * The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
 * exported by this module:
 *
 * Traditional:
 *
 * - {@link KEM_DHKEM_P256_HKDF_SHA256 | DHKEM(P-256, HKDF-SHA256)}
 * - {@link KEM_DHKEM_P384_HKDF_SHA384 | DHKEM(P-384, HKDF-SHA384)}
 * - {@link KEM_DHKEM_P521_HKDF_SHA512 | DHKEM(P-521, HKDF-SHA512)}
 * - {@link KEM_DHKEM_X25519_HKDF_SHA256 | DHKEM(X25519, HKDF-SHA256)}
 * - {@link KEM_DHKEM_X448_HKDF_SHA512 | DHKEM(X448, HKDF-SHA512)}
 *
 * Post-quantum/Traditional (PQ/T Hybrid):
 *
 * - {@link KEM_MLKEM768_P256 | MLKEM768-P256}
 * - {@link KEM_MLKEM768_X25519 | MLKEM768-X25519 (aka X-Wing)}
 * - {@link KEM_MLKEM1024_P384 | MLKEM1024-P384}
 *
 * Post-quantum (PQ):
 *
 * - {@link KEM_ML_KEM_512 | ML-KEM-512}
 * - {@link KEM_ML_KEM_768 | ML-KEM-768}
 * - {@link KEM_ML_KEM_1024 | ML-KEM-1024}
 *
 * > [!TIP]\
 * > {@link CipherSuite} is not limited to using only these exported KEM implementations. Any function
 * > returning an object conforming to the {@link KEM} interface can be used. Such implementations not
 * > reliant on Web Cryptography are exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 */
export type KEMFactory = () => Readonly<KEM>

/**
 * Factory function that returns a KDF implementation.
 *
 * The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
 * exported by this module:
 *
 * - {@link KDF_HKDF_SHA256 | HKDF-SHA256}
 * - {@link KDF_HKDF_SHA384 | HKDF-SHA384}
 * - {@link KDF_HKDF_SHA512 | HKDF-SHA512}
 * - {@link KDF_SHAKE128 | SHAKE128}
 * - {@link KDF_SHAKE256 | SHAKE256}
 *
 * > [!TIP]\
 * > {@link CipherSuite} is not limited to using only these exported KDF implementations. Any function
 * > returning an object conforming to the {@link KDF} interface can be used. Such implementations not
 * > reliant on Web Cryptography are exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 */
export type KDFFactory = () => Readonly<KDF>

/**
 * Factory function that returns an AEAD implementation.
 *
 * The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
 * exported by this module:
 *
 * - {@link AEAD_AES_128_GCM | AES-128-GCM}
 * - {@link AEAD_AES_256_GCM | AES-256-GCM}
 * - {@link AEAD_ChaCha20Poly1305 | ChaCha20Poly1305}
 * - {@link AEAD_EXPORT_ONLY | Export-only}
 *
 * > [!TIP]\
 * > {@link CipherSuite} is not limited to using only these exported AEAD implementations. Any function
 * > returning an object conforming to the {@link AEAD} interface can be used. Such implementations not
 * > reliant on Web Cryptography are exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 */
export type AEADFactory = () => Readonly<AEAD>

/**
 * Represents a cryptographic key pair consisting of a public key and private key.
 *
 * These keys are used throughout HPKE for key encapsulation mechanisms (KEM). Key pairs are
 * randomly generated using {@link CipherSuite.GenerateKeyPair} or deterministically derived from a
 * seed using {@link CipherSuite.DeriveKeyPair}.
 *
 * Key Usage:
 *
 * - Public Key: Used by senders for encryption operations (passed to {@link CipherSuite.SetupSender}
 *   or {@link CipherSuite.Seal}). These keys are distributed by recipients.
 * - Private Key: Used by recipients for decryption operations (passed to
 *   {@link CipherSuite.SetupRecipient} or {@link CipherSuite.Open}). These are not distributed and
 *   kept private.
 */
export interface KeyPair {
  /** The public key, used for encryption operations. */
  readonly publicKey: Readonly<Key>
  /** The private key, used for decryption operations. */
  readonly privateKey: Readonly<Key>
}

/**
 * A minimal key representation interface.
 *
 * This interface is designed to be compatible with Web Cryptography's CryptoKey objects while
 * allowing for custom key implementations that may not have all CryptoKey properties. It includes
 * only the essential properties needed for HPKE operations and validations.
 */
export interface Key {
  /** The key algorithm properties */
  readonly algorithm: {
    /** The algorithm identifier for the key. */
    name: string
  }

  /** Whether the key material can be extracted. */
  readonly extractable: boolean

  /** The type of key: 'private' or 'public' */
  readonly type: 'private' | 'public' | (string & {})
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Concatenates multiple Uint8Array buffers into a single Uint8Array. It's exported for use in
 * custom KEM, KDF, or AEAD implementations.
 *
 * @param buffers - Variable number of Uint8Array buffers to concatenate
 *
 * @returns A new Uint8Array containing all input buffers concatenated in order
 * @group Utilities
 */
export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  for (const buffer of buffers) {
    buf.set(buffer, i)
    i += buffer.length
  }
  return buf
}

function slice(buffer: Uint8Array, start?: number, end?: number) {
  return Uint8Array.prototype.slice.call(buffer, start, end)
}

/**
 * Encodes an ASCII string into a Uint8Array.
 *
 * This utility function converts ASCII strings to byte arrays. It's exported for use in custom KEM,
 * KDF, or AEAD implementations.
 *
 * @param string - ASCII string to encode
 *
 * @returns A Uint8Array containing the ASCII byte values
 * @group Utilities
 */
export function encode(string: string): Uint8Array {
  const bytes = new Uint8Array(string.length)
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i)
    bytes[i] = code
  }
  return bytes
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.byteLength !== b.byteLength) {
    throw new Error('XOR operands must have equal length')
  }
  const buf = new Uint8Array(a.byteLength)
  for (let i = 0; i < a.byteLength; i++) {
    buf[i] = a[i]! ^ b[i]!
  }
  return buf
}

function lengthPrefixed(x: Uint8Array): Uint8Array {
  return concat(I2OSP(x.byteLength, 2), x)
}

// ============================================================================
// KDF (Key Derivation Function) - Helper Functions
// ============================================================================

/**
 * Performs labeled key derivation for one-stage KDFs.
 *
 * This function implements the LabeledDerive operation as specified in the HPKE specification for
 * use with one-stage KDFs. It constructs a labeled input by concatenating:
 *
 * - The input keying material (`ikm`)
 * - The version string "HPKE-v1"
 * - The suite identifier (`suite_id`)
 * - A length-prefixed label
 * - The desired output length as a 2-byte encoding
 * - Additional context
 *
 * The labeled input is then passed to the KDF's Derive function to produce L bytes of output. This
 * ensures domain separation between different uses of the KDF in HPKE.
 *
 * @group Utilities
 */
export async function LabeledDerive(
  KDF: Pick<KDF, 'Derive'>,
  suite_id: Uint8Array,
  ikm: Uint8Array,
  label: Uint8Array,
  context: Uint8Array,
  L: number,
): Promise<Uint8Array> {
  const labeled_ikm = concat(
    ikm,
    encode('HPKE-v1'),
    suite_id,
    lengthPrefixed(label),
    I2OSP(L, 2),
    context,
  )
  return await KDF.Derive(labeled_ikm, L)
}

async function ExportOneStage(
  KDF: KDF,
  suite_id: Uint8Array,
  exporter_secret: Uint8Array,
  exporter_context: Uint8Array,
  L: number,
) {
  if (exporter_context.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `Exporter context length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  return await LabeledDerive(KDF, suite_id, exporter_secret, encode('sec'), exporter_context, L)
}

async function CombineSecretsOneStage(
  suite: Triple,
  mode: number,
  shared_secret: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array,
  psk_id: Uint8Array,
) {
  if (psk.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `PSK length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  if (psk_id.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `PSK ID length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  if (info.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `Info length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }

  const secrets = concat(lengthPrefixed(psk), lengthPrefixed(shared_secret))
  const context = concat(I2OSP(mode, 1), lengthPrefixed(psk_id), lengthPrefixed(info))

  const secret = await LabeledDerive(
    suite.KDF,
    suite.id,
    secrets,
    encode('secret'),
    context,
    suite.AEAD.Nk + suite.AEAD.Nn + suite.KDF.Nh,
  )

  const key = slice(secret, 0, suite.AEAD.Nk)
  const base_nonce = slice(secret, suite.AEAD.Nk, suite.AEAD.Nk + suite.AEAD.Nn)
  const exporter_secret = slice(secret, suite.AEAD.Nk + suite.AEAD.Nn)

  return { key, base_nonce, exporter_secret }
}

// Two-stage KDF input length limits (0xffff = 65535 bytes)
// this is an actual limit for One-Stage KDF
const MAX_LENGTH_TWO_STAGE = 0xffff
// that is also applied to Two-Stage KDF for consistency
const MAX_LENGTH_ONE_STAGE = 0xffff

async function CombineSecretsTwoStage(
  suite: Triple,
  mode: number,
  shared_secret: Uint8Array,
  info: Uint8Array,
  psk: Uint8Array,
  psk_id: Uint8Array,
) {
  if (psk.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `PSK length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  if (psk_id.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `PSK ID length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  if (info.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `Info length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }

  const [psk_id_hash, info_hash] = await Promise.all([
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), encode('psk_id_hash'), psk_id),
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), encode('info_hash'), info),
  ])

  const key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
  const secret = await LabeledExtract(suite.KDF, suite.id, shared_secret, encode('secret'), psk)

  // For export-only AEAD, we only need the exporter_secret
  if (suite.AEAD.id === EXPORT_ONLY) {
    const exporter_secret = await LabeledExpand(
      suite.KDF,
      suite.id,
      secret,
      encode('exp'),
      key_schedule_context,
      suite.KDF.Nh,
    )
    return { key: new Uint8Array(), base_nonce: new Uint8Array(), exporter_secret }
  }

  const [key, base_nonce, exporter_secret] = await Promise.all([
    LabeledExpand(suite.KDF, suite.id, secret, encode('key'), key_schedule_context, suite.AEAD.Nk),
    LabeledExpand(
      suite.KDF,
      suite.id,
      secret,
      encode('base_nonce'),
      key_schedule_context,
      suite.AEAD.Nn,
    ),
    LabeledExpand(suite.KDF, suite.id, secret, encode('exp'), key_schedule_context, suite.KDF.Nh),
  ])

  return { key, base_nonce, exporter_secret }
}

async function ExportTwoStage(
  KDF: KDF,
  suite_id: Uint8Array,
  exporter_secret: Uint8Array,
  exporter_context: Uint8Array,
  L: number,
) {
  if (exporter_context.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `Exporter context length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  return await LabeledExpand(KDF, suite_id, exporter_secret, encode('sec'), exporter_context, L)
}

/**
 * Key Derivation Function (KDF) implementation interface.
 *
 * This implementation interface defines the contract for additional KDF implementations to be
 * usable with {@link CipherSuite}. While this module provides built-in KDF implementations based on
 * [Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
 * custom KDF implementations that may not rely on Web Cryptography (e.g., using native bindings,
 * alternative crypto libraries, or specialized hardware).
 *
 * Custom KDF implementations must conform to this interface to be compatible with
 * {@link CipherSuite} and its APIs.
 *
 * KDF implementations are either one-stage or two-stage:
 *
 * - One-stage KDFs only implement {@link Derive}. The {@link Extract} and {@link Expand} methods will
 *   not be called and may be no-op implementations.
 * - Two-stage KDFs only implement {@link Extract} and {@link Expand}. The {@link Derive} method will not
 *   be called and may be a no-op implementation.
 *
 * @example
 *
 * ```ts
 * import * as HPKE from '@panva/hpke'
 *
 * // Using a built-in KDF
 * const suite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   HPKE.KDF_HKDF_SHA256,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 *
 * // Creating and using a custom KDF implementation
 * const customKDF: HPKE.KDFFactory = (): HPKE.KDF => ({
 *   id: 0x9999,
 *   type: 'KDF',
 *   name: 'Custom-KDF',
 *   Nh: 32,
 *   stages: 2,
 *   async Extract(salt, ikm) {
 *     // perform Extract
 *     let result!: Uint8Array
 *
 *     return result
 *   },
 *   async Expand(prk, info, L) {
 *     // perform Expand
 *     let result!: Uint8Array
 *
 *     return result
 *   },
 *   async Derive(labeled_ikm, L) {
 *     // perform Derive
 *     let result!: Uint8Array
 *
 *     return result
 *   },
 * })
 *
 * const customSuite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   customKDF,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 * ```
 *
 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface KDF {
  /** KDF algorithm identifier */
  readonly id: number

  /** Type discriminator, always 'KDF' */
  readonly type: 'KDF'

  /** Human-readable name of the KDF algorithm */
  readonly name: string

  /**
   * For one-stage KDFs, the security strength of the KDF in bytes.
   *
   * For two-stage KDFs, the output size of the {@link Extract} function in bytes.
   */
  readonly Nh: number

  /** Number of stages (1 or 2) indicating one-stage or two-stage KDF */
  readonly stages: 1 | 2

  /**
   * Extracts a pseudorandom key from input keying material.
   *
   * @param salt - Salt value
   * @param ikm - Input keying material
   *
   * @returns A promise resolving to the pseudorandom key
   */
  Extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>

  /**
   * Expands a pseudorandom key to the desired length.
   *
   * @param prk - Pseudorandom key
   * @param info - Context and application-specific information
   * @param L - Desired length of output keying material in bytes
   *
   * @returns A promise resolving to the output keying material
   */
  Expand(prk: Uint8Array, info: Uint8Array, L: number): Promise<Uint8Array>

  /**
   * Derives output keying material directly from labeled input keying material.
   *
   * @param labeled_ikm - Labeled input keying material
   * @param L - Desired length of output keying material in bytes
   *
   * @returns A promise resolving to the output keying material
   */
  Derive(labeled_ikm: Uint8Array, L: number): Promise<Uint8Array>
}

// ============================================================================
// KDF (Key Derivation Function) - Labeled Extract/Expand Functions
// ============================================================================

/**
 * Performs labeled extraction for two-stage KDFs.
 *
 * This function implements the LabeledExtract operation as specified in the HPKE specification for
 * use with two-stage KDFs. It constructs a labeled input by concatenating:
 *
 * - The version string "HPKE-v1"
 * - The suite identifier (`suite_id`)
 * - The label
 * - The input keying material (`ikm`)
 *
 * The labeled input is then passed to the KDF's Extract function along with the salt to produce a
 * pseudorandom key. This ensures domain separation between different uses of the KDF in HPKE.
 *
 * @group Utilities
 */
export async function LabeledExtract(
  KDF: Pick<KDF, 'Extract'>,
  suite_id: Uint8Array,
  salt: Uint8Array,
  label: Uint8Array,
  ikm: Uint8Array,
): Promise<Uint8Array> {
  const labeled_ikm = concat(encode('HPKE-v1'), suite_id, label, ikm)
  return await KDF.Extract(salt, labeled_ikm)
}

/**
 * Performs labeled expansion for two-stage KDFs.
 *
 * This function implements the LabeledExpand operation as specified in the HPKE specification for
 * use with two-stage KDFs. It constructs a labeled info string by concatenating:
 *
 * - The desired output length as a 2-byte encoding
 * - The version string "HPKE-v1"
 * - The suite identifier (`suite_id`)
 * - The label
 * - Additional info context
 *
 * The labeled info is then passed to the KDF's Expand function along with the pseudorandom key to
 * produce L bytes of output keying material. This ensures domain separation between different uses
 * of the KDF in HPKE.
 *
 * @group Utilities
 */
export async function LabeledExpand(
  KDF: Pick<KDF, 'Expand'>,
  suite_id: Uint8Array,
  prk: Uint8Array,
  label: Uint8Array,
  info: Uint8Array,
  L: number,
): Promise<Uint8Array> {
  const labeled_info = concat(I2OSP(L, 2), encode('HPKE-v1'), suite_id, label, info)
  return await KDF.Expand(prk, labeled_info, L)
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - Types and Interfaces
// ============================================================================

/**
 * Key Encapsulation Mechanism (KEM) implementation interface.
 *
 * This implementation interface defines the contract for additional KEM implementations to be
 * usable with {@link CipherSuite}. While this module provides built-in KEM implementations based on
 * [Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
 * custom KEM implementations that may not rely on Web Cryptography (e.g., using native bindings,
 * alternative crypto libraries, or specialized hardware).
 *
 * Custom KEM implementations must conform to this interface to be compatible with
 * {@link CipherSuite} and its APIs.
 *
 * @example
 *
 * ```ts
 * import * as HPKE from '@panva/hpke'
 *
 * // Using a built-in KEM
 * const suite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   HPKE.KDF_HKDF_SHA256,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 *
 * // Creating and using a custom KEM implementation
 * const customKEM: HPKE.KEMFactory = (): HPKE.KEM => ({
 *   id: 0x9999,
 *   type: 'KEM',
 *   name: 'Custom-KEM',
 *   Nsecret: 32,
 *   Nenc: 32,
 *   Npk: 32,
 *   Nsk: 32,
 *   async DeriveKeyPair(ikm, extractable) {
 *     // perform DeriveKeyPair
 *     let kp!: HPKE.KeyPair
 *
 *     return kp
 *   },
 *   async GenerateKeyPair(extractable) {
 *     // perform GenerateKeyPair
 *     let kp!: HPKE.KeyPair
 *
 *     return kp
 *   },
 *   async SerializePublicKey(key) {
 *     // perform SerializePublicKey
 *     let publicKey!: Uint8Array
 *
 *     return publicKey
 *   },
 *   async DeserializePublicKey(key) {
 *     // perform DeserializePublicKey
 *     let publicKey!: HPKE.Key
 *
 *     return publicKey
 *   },
 *   async SerializePrivateKey(key) {
 *     // perform SerializePrivateKey
 *     let privateKey!: Uint8Array
 *
 *     return privateKey
 *   },
 *   async DeserializePrivateKey(key, extractable) {
 *     // perform DeserializePrivateKey
 *     let privateKey!: HPKE.Key
 *
 *     return privateKey
 *   },
 *   async Encap(pkR) {
 *     // perform Encap
 *     let shared_secret!: Uint8Array
 *     let enc!: Uint8Array
 *
 *     return { shared_secret, enc }
 *   },
 *   async Decap(enc, skR, pkR) {
 *     // perform Decap
 *     let shared_secret!: Uint8Array
 *
 *     return shared_secret
 *   },
 * })
 *
 * const customSuite = new HPKE.CipherSuite(
 *   customKEM,
 *   HPKE.KDF_HKDF_SHA256,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 * ```
 *
 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface KEM {
  /** KEM algorithm identifier */
  readonly id: number

  /** Type discriminator, always 'KEM' */
  readonly type: 'KEM'

  /** Human-readable name of the KEM algorithm */
  readonly name: string

  /** Length in bytes of a KEM shared secret produced by this KEM */
  readonly Nsecret: number

  /** Length in bytes of an encapsulated secret produced by this KEM */
  readonly Nenc: number

  /** Length in bytes of a public key for this KEM */
  readonly Npk: number

  /** Length in bytes of a private key for this KEM */
  readonly Nsk: number

  /**
   * Derives a key pair deterministically from input keying material.
   *
   * @param ikm - Input keying material already validated to be at least {@link Nsk} bytes
   * @param extractable - Whether the private key should be extractable
   *
   * @returns A promise resolving to a {@link KeyPair}
   */
  DeriveKeyPair(ikm: Uint8Array, extractable: boolean): Promise<KeyPair>

  /**
   * Generates a random key pair.
   *
   * @param extractable - Whether the private key should be extractable
   *
   * @returns A promise resolving to a {@link KeyPair}
   */
  GenerateKeyPair(extractable: boolean): Promise<KeyPair>

  /**
   * Serializes a public key to bytes.
   *
   * @param key - The public Key to serialize
   *
   * @returns A promise resolving to the serialized public key
   */
  SerializePublicKey(key: Key): Promise<Uint8Array>

  /**
   * Deserializes a public key from bytes.
   *
   * @param key - The serialized public key already validated to be at least {@link Npk} bytes
   *
   * @returns A promise resolving to a {@link !Key} or a Key interface-conforming object
   */
  DeserializePublicKey(key: Uint8Array): Promise<Key>

  /**
   * Serializes a private key to bytes.
   *
   * @param key - The private Key to serialize
   *
   * @returns A promise resolving to the serialized private key
   */
  SerializePrivateKey(key: Key): Promise<Uint8Array>

  /**
   * Deserializes a private key from bytes.
   *
   * @param key - The serialized private key already validated to be at least {@link Nsk} bytes
   * @param extractable - Whether the private key should be extractable
   *
   * @returns A promise resolving to a {@link !Key} or a Key interface-conforming object
   */
  DeserializePrivateKey(key: Uint8Array, extractable: boolean): Promise<Key>

  /**
   * Encapsulates a shared secret to a recipient's public key.
   *
   * This is the sender-side operation that generates an ephemeral key pair, performs the KEM
   * operation, and returns both the shared secret and the encapsulated secret to send to the
   * recipient.
   *
   * @param pkR - The recipient's public key
   *
   * @returns A promise resolving to an object containing the shared secret and encapsulated secret
   */
  Encap(pkR: Key): Promise<{ shared_secret: Uint8Array; enc: Uint8Array }>

  /**
   * Decapsulates a shared secret using a recipient's private key.
   *
   * This is the recipient-side operation that uses the private key to extract the shared secret
   * from the encapsulated secret.
   *
   * @param enc - The encapsulated secret of {@link Nenc} length
   * @param skR - The recipient's private key
   * @param pkR - The recipient's public key (when user input to {@link CipherSuite.SetupRecipient}
   *   is a {@link KeyPair})
   *
   * @returns A promise resolving to the shared secret
   */
  Decap(enc: Uint8Array, skR: Key, pkR: Key | undefined): Promise<Uint8Array>
}

function isKeyPair(skR: unknown): skR is KeyPair {
  if (!skR || typeof skR !== 'object') return false
  if ('publicKey' in skR && 'privateKey' in skR) {
    const pkR = skR.publicKey
    skR = skR.privateKey
    try {
      isKey(pkR, 'public')
      isKey(skR, 'private')
      if (pkR.algorithm.name !== skR.algorithm.name) {
        throw new TypeError('key pair algorithms do not match')
      }
    } catch (cause) {
      throw new TypeError('Invalid "privateKey"', { cause })
    }
    return true
  }
  return false
}

function isKey(key: unknown, type: string, extractable?: boolean): asserts key is Key {
  const k = key as Key
  if (
    typeof k.algorithm !== 'object' ||
    typeof k.algorithm.name !== 'string' ||
    typeof k.extractable !== 'boolean' ||
    typeof k.type !== 'string' ||
    k.type !== type
  ) {
    throw new TypeError(`Invalid "${type}Key"`)
  }

  if (extractable && k.extractable !== true) {
    throw new TypeError(`"${type}Key" must be extractable`)
  }
}

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data) - Types and Interface
// ============================================================================

/**
 * Authenticated Encryption with Associated Data (AEAD) implementation interface.
 *
 * This implementation interface defines the contract for additional AEAD implementations to be
 * usable with {@link CipherSuite}. While this module provides built-in AEAD implementations based on
 * [Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
 * custom AEAD implementations that may not rely on Web Cryptography (e.g., using native bindings,
 * alternative crypto libraries, or specialized hardware).
 *
 * Custom AEAD implementations must conform to this interface to be compatible with
 * {@link CipherSuite} and its APIs.
 *
 * @example
 *
 * ```ts
 * import * as HPKE from '@panva/hpke'
 *
 * // Using a built-in AEAD
 * const suite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   HPKE.KDF_HKDF_SHA256,
 *   HPKE.AEAD_AES_128_GCM,
 * )
 *
 * // Creating and using a custom AEAD implementation
 * const customAEAD: HPKE.AEADFactory = (): HPKE.AEAD => ({
 *   id: 0x9999,
 *   type: 'AEAD',
 *   name: 'Custom-AEAD',
 *   Nk: 16,
 *   Nn: 12,
 *   Nt: 16,
 *   async Seal(key, nonce, aad, pt) {
 *     // perform AEAD
 *     let ciphertext!: Uint8Array
 *
 *     return ciphertext
 *   },
 *   async Open(key, nonce, aad, ct) {
 *     // perform AEAD
 *     let plaintext!: Uint8Array
 *
 *     return plaintext
 *   },
 * })
 *
 * const customSuite = new HPKE.CipherSuite(
 *   HPKE.KEM_DHKEM_P256_HKDF_SHA256,
 *   HPKE.KDF_HKDF_SHA256,
 *   customAEAD,
 * )
 * ```
 *
 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface AEAD {
  /** AEAD algorithm identifier */
  readonly id: number

  /** Type discriminator, always 'AEAD' */
  readonly type: 'AEAD'

  /** Human-readable name of the AEAD algorithm */
  readonly name: string

  /** Length in bytes of a key for this AEAD */
  readonly Nk: number

  /** Length in bytes of a nonce for this AEAD */
  readonly Nn: number

  /** Length in bytes of the authentication tag for this AEAD */
  readonly Nt: number

  /**
   * Encrypts and authenticates plaintext with associated data.
   *
   * @param key - The encryption key of {@link Nk} bytes
   * @param nonce - The nonce of {@link Nn} bytes
   * @param aad - Additional authenticated data
   * @param pt - Plaintext to encrypt
   *
   * @returns A promise resolving to the ciphertext with authentication tag appended
   */
  Seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array>

  /**
   * Decrypts and verifies ciphertext with associated data.
   *
   * @param key - The decryption key of {@link Nk} bytes
   * @param nonce - The nonce of {@link Nn} bytes
   * @param aad - Additional authenticated data
   * @param ct - Ciphertext with authentication tag appended
   *
   * @returns A promise resolving to the decrypted plaintext
   */
  Open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array>
}

// ============================================================================
// HPKE Core Functions - Key Schedule
// ============================================================================

/**
 * Integer to Octet String Primitive (I2OSP) as defined in RFC 8017. Converts a non-negative integer
 * into a byte string of specified length. It's exported for use in custom KEM, KDF, or AEAD
 * implementations.
 *
 * @param n - Non-negative integer to convert
 * @param w - Desired length of output in bytes
 *
 * @returns A Uint8Array of length w containing the big-endian representation of n
 * @group Utilities
 */
export function I2OSP(n: number, w: number): Uint8Array {
  if (!Number.isSafeInteger(w) || w <= 0) {
    throw new Error('w must be a positive integer')
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error('n must be a nonnegative integer')
  }
  const max = Math.pow(256, w)
  if (n >= max) {
    throw new Error('n too large')
  }
  const ret = new Uint8Array(w)
  let num = n
  for (let i = 0; i < w && num; i++) {
    ret[w - (i + 1)] = num % 256
    num = Math.floor(num / 256)
  }
  return ret
}

function KDFStages(KDF: KDF): 1 | 2 {
  if (KDF.stages === 1 || KDF.stages === 2) {
    return KDF.stages
  }
  /* c8 ignore next */
  throw new Error('unreachable')
}

async function KeySchedule(
  suite: Triple,
  mode: number,
  shared_secret: Uint8Array,
  info?: Uint8Array,
  psk?: Uint8Array,
  pskId?: Uint8Array,
) {
  if (info != null && !(info instanceof Uint8Array)) {
    throw new TypeError('"info" must be an Uint8Array')
  }
  if (psk != null && !(psk instanceof Uint8Array)) {
    throw new TypeError('"psk" must be an Uint8Array')
  }
  if (pskId != null && !(pskId instanceof Uint8Array)) {
    throw new TypeError('"pskId" must be an Uint8Array')
  }
  VerifyPSKInputs(psk, pskId)

  info ??= new Uint8Array()
  psk ??= new Uint8Array()
  pskId ??= new Uint8Array()

  const stages = KDFStages(suite.KDF)
  const CombineSecrets = stages === 1 ? CombineSecretsOneStage : CombineSecretsTwoStage

  return await CombineSecrets(suite, mode, shared_secret, info, psk, pskId)
}

function VerifyPSKInputs(psk?: Uint8Array, psk_id?: Uint8Array) {
  if (psk?.byteLength && psk_id?.byteLength) {
    if (psk.byteLength < 32) {
      throw new TypeError('Insufficient PSK length')
    }
    return
  }
  if (!psk?.byteLength && !psk_id?.byteLength) {
    return
  }
  throw new TypeError('Inconsistent PSK inputs')
}

/* c8 ignore next 3 */
const NotApplicable = () => {
  throw new Error('unreachable')
}

const EXPORT_ONLY = 0xffff
/**
 * Export-only AEAD mode.
 *
 * A special AEAD mode that disables encryption/decryption operations and only allows key export
 * functionality. Used when HPKE is employed solely for key agreement and derivation, not for
 * message encryption. Cannot be used with Seal/Open operations.
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * @group AEAD Algorithms
 */
export const AEAD_EXPORT_ONLY: AEADFactory = function (): AEAD {
  return {
    id: EXPORT_ONLY,
    type: 'AEAD',
    name: 'Export-only',
    Nk: 0,
    Nn: 0,
    Nt: 0,
    Seal: NotApplicable,
    Open: NotApplicable,
  }
}

// ============================================================================
// Crypto.subtle wrapper to convert DOMException NotSupportedError
// ============================================================================

async function subtle<T>(promise: () => Promise<T>, name: string): Promise<T> {
  try {
    return await promise()
  } catch (cause) {
    if (
      cause instanceof TypeError ||
      (cause instanceof DOMException && cause.name === 'NotSupportedError')
    ) {
      throw new NotSupportedError(`${name} is unsupported in this runtime`, { cause })
    }
    throw cause
  }
}

interface HKDF extends KDF {
  readonly hash: string
}

type KDF_BASE = Pick<KDF, 'Expand' | 'Extract' | 'Derive' | 'stages'>

function sab(input: ArrayBufferLike): input is SharedArrayBuffer {
  return typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer
}

function ab(input: Uint8Array): ArrayBuffer {
  if (sab(input.buffer)) {
    throw new TypeError('input must not be a SharedArrayBuffer')
  }
  if (input.byteLength === input.buffer.byteLength) {
    return input.buffer
  }
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
}

function HKDF_SHARED(): KDF_BASE {
  return {
    stages: 2,
    Derive: NotApplicable,
    async Extract(this: HKDF, _salt, _ikm) {
      let salt: ArrayBuffer
      if (_salt.byteLength === 0) {
        salt = new ArrayBuffer(this.Nh)
      } else {
        salt = ab(_salt)
      }
      const ikm = ab(_ikm)
      return new Uint8Array(
        await subtle(
          async () =>
            crypto.subtle.sign(
              'HMAC',
              await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: this.hash }, false, [
                'sign',
              ]),
              ikm,
            ),
          this.name,
        ),
      )
    },
    async Expand(this: HKDF, _prk, info, L) {
      if (_prk.byteLength < this.Nh) {
        throw new Error('prk.byteLength < this.Nh')
      }
      if (L > 255 * this.Nh) {
        throw new Error('L must be <= 255*Nh')
      }
      const N = Math.ceil(L / this.Nh)
      const prk = ab(_prk)
      const key = await subtle(
        () =>
          crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: this.hash }, false, ['sign']),
        this.name,
      )

      const T = new Uint8Array(N * this.Nh)
      let T_prev = new Uint8Array()

      for (let i = 0; i < N; i++) {
        const input = new Uint8Array(T_prev.byteLength + info.byteLength + 1)
        input.set(T_prev)
        input.set(info, T_prev.byteLength)
        input[T_prev.byteLength + info.byteLength] = i + 1

        const T_i = new Uint8Array(
          await subtle(() => crypto.subtle.sign('HMAC', key, input), this.name),
        )

        T.set(T_i, i * this.Nh)
        T_prev = T_i
      }

      return slice(T, 0, L)
    },
  }
}

// ============================================================================
// KDF (Key Derivation Function) - HKDF Implementations
// ============================================================================

/**
 * HKDF-SHA256 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-256 as the
 * hash function with an output length (Nh) of 32 bytes.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - HMAC with SHA-256
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KDF Algorithms
 */
export const KDF_HKDF_SHA256: KDFFactory = function (): HKDF {
  return { id: 0x0001, type: 'KDF', name: 'HKDF-SHA256', Nh: 32, hash: 'SHA-256', ...HKDF_SHARED() }
}

/**
 * HKDF-SHA384 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-384 as the
 * hash function with an output length (Nh) of 48 bytes.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - HMAC with SHA-384
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KDF Algorithms
 */
export const KDF_HKDF_SHA384: KDFFactory = function (): HKDF {
  return { id: 0x0002, type: 'KDF', name: 'HKDF-SHA384', Nh: 48, hash: 'SHA-384', ...HKDF_SHARED() }
}

/**
 * HKDF-SHA512 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-512 as the
 * hash function with an output length (Nh) of 64 bytes.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - HMAC with SHA-512
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KDF Algorithms
 */
export const KDF_HKDF_SHA512: KDFFactory = function (): HKDF {
  return { id: 0x0003, type: 'KDF', name: 'HKDF-SHA512', Nh: 64, hash: 'SHA-512', ...HKDF_SHARED() }
}

// ============================================================================
// KDF (Key Derivation Function) - SHAKE Implementations
// ============================================================================

interface SHAKE extends KDF {
  readonly algorithm: string
}

async function ShakeDerive(name: string, variant: string, ikm: ArrayBuffer, L: number) {
  return new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.digest(
          {
            name: variant,
            // @ts-expect-error
            length: L << 3,
          },
          ikm,
        ),
      name,
    ),
  )
}

function SHAKE_SHARED(): KDF_BASE {
  return {
    stages: 1,
    async Derive(this: SHAKE, labeled_ikm, L: number) {
      return await ShakeDerive(this.name, this.algorithm, ab(labeled_ikm), L)
    },
    Extract: NotApplicable,
    Expand: NotApplicable,
  }
}

/**
 * SHAKE128 key derivation function.
 *
 * A one-stage KDF using the SHAKE128 extendable-output function (XOF) with an output length (Nh) of
 * 32 bytes.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - SHAKE128 (cSHAKE128 without any parameters) digest
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KDF Algorithms
 */
export const KDF_SHAKE128: KDFFactory = function (): SHAKE {
  return {
    id: 0x0010,
    type: 'KDF',
    name: 'SHAKE128',
    Nh: 32,
    algorithm: 'cSHAKE128',
    ...SHAKE_SHARED(),
  }
}

/**
 * SHAKE256 key derivation function.
 *
 * A one-stage KDF using the SHAKE256 extendable-output function (XOF) with an output length (Nh) of
 * 64 bytes.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - SHAKE256 (cSHAKE256 without any parameters) digest
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KDF Algorithms
 */
export const KDF_SHAKE256: KDFFactory = function (): SHAKE {
  return {
    id: 0x0011,
    type: 'KDF',
    name: 'SHAKE256',
    Nh: 64,
    algorithm: 'cSHAKE256',
    ...SHAKE_SHARED(),
  }
}

async function getPublicKeyByExport(
  name: string,
  key: CryptoKey,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  if (!key.extractable) {
    throw new TypeError(
      '"privateKey" must be extractable or a Key Pair must be used in this runtime',
    )
  }

  return await subtle(async () => {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    return await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey,
      key.algorithm,
      true,
      usages,
    )
  }, name)
}

async function getPublicKey(name: string, key: CryptoKey, usages: KeyUsage[]): Promise<CryptoKey> {
  return (
    // @ts-expect-error
    ((await subtle(() => crypto.subtle.getPublicKey?.(key, usages), name)) as CryptoKey) ||
    (await getPublicKeyByExport(name, key, usages))
  )
}

/** This is a last resort check, Web Cryptography implementers should already be checking it */
function checkNotAllZeros(buffer: Uint8Array): void {
  let allZeros = 1
  for (let i = 0; i < buffer.length; i++) {
    allZeros &= buffer[i]! === 0 ? 1 : 0
  }
  if (allZeros === 1) {
    throw new ValidationError('DH shared secret is an all-zero value')
  }
}

type KEM_BASE = Pick<
  KEM,
  | 'GenerateKeyPair'
  | 'DeriveKeyPair'
  | 'SerializePublicKey'
  | 'DeserializePublicKey'
  | 'SerializePrivateKey'
  | 'DeserializePrivateKey'
  | 'Encap'
  | 'Decap'
>

interface DHKEM extends KEM {
  readonly suite_id: Uint8Array
  readonly Ndh: number
  readonly kdf: KDF
  readonly algorithm: Readonly<KeyAlgorithm | EcKeyAlgorithm>
}

function fromBase64(input: string) {
  input = input.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(input)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!)
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function toB64u(input: Uint8Array) {
  // @ts-ignore
  return input.toBase64?.({ alphabet: 'base64url', omitPadding: true }) || toBase64Url(input)
}

function b64u(input: string): Uint8Array {
  // @ts-ignore
  return Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fromBase64(input)
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM Helper Functions
// ============================================================================

async function DeriveCandidate(
  DHKEM: DHKEM,
  suite_id: Uint8Array,
  ikm: Uint8Array,
  counter: number,
) {
  const dkp_prk = await LabeledExtract(
    DHKEM.kdf,
    suite_id,
    new Uint8Array(),
    encode('dkp_prk'),
    ikm,
  )
  return await LabeledExpand(
    DHKEM.kdf,
    suite_id,
    dkp_prk,
    encode('candidate'),
    I2OSP(counter, 1),
    DHKEM.Nsk,
  )
}

function OS2IP(x: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < x.byteLength; i++) {
    result = result * 256n + BigInt(x[i]!)
  }
  return result
}

function bigIntToUint8Array(value: bigint, byteLength: number): Uint8Array {
  const result = new Uint8Array(byteLength)
  let n = value

  for (let i = byteLength - 1; i >= 0; i--) {
    result[i] = Number(n & 0xffn)
    n = n >> 8n
  }

  return result
}

function assertKeyAlgorithm(key: Key, expectedAlgorithm: KeyAlgorithm) {
  if (key.algorithm.name !== expectedAlgorithm.name) {
    throw new TypeError(`key algorithm must be ${expectedAlgorithm.name}`)
  }
  if (
    (key.algorithm as EcKeyAlgorithm).namedCurve !==
    (expectedAlgorithm as EcKeyAlgorithm).namedCurve
  ) {
    throw new TypeError(
      `key namedCurve must be ${(expectedAlgorithm as EcKeyAlgorithm).namedCurve}`,
    )
  }
}

function assertCryptoKey(key: Key): asserts key is CryptoKey {
  // @ts-expect-error
  if (key[Symbol.toStringTag] !== 'CryptoKey') {
    if (key instanceof CryptoKey) return
    throw new TypeError('unexpected key constructor')
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM Shared Implementation
// ============================================================================

function DHKEM_SHARED(): Required<Omit<KEM_BASE, 'DeriveKeyPair' | 'DeserializePrivateKey'>> {
  return {
    async GenerateKeyPair(this: DHKEM, extractable) {
      return (await subtle(
        () => crypto.subtle.generateKey(this.algorithm, extractable, ['deriveBits']),
        this.name,
      )) as CryptoKeyPair
    },
    async SerializePublicKey(this: DHKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey('raw', key), this.name))
    },
    async DeserializePublicKey(this: DHKEM, _key) {
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey('raw', key, this.algorithm, true, []),
        this.name,
      )
    },
    async SerializePrivateKey(this: DHKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      const { d } = await subtle(() => crypto.subtle.exportKey('jwk', key), this.name)
      return b64u(d!)
    },
    async Encap(this: DHKEM, pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      assertCryptoKey(pkR)

      const ekp = (await this.GenerateKeyPair(false)) as CryptoKeyPair
      const skE = ekp.privateKey
      const pkE = ekp.publicKey

      // DH all-zero/point at infinity checks are performed
      // by WebCrypto's underlying implementations
      const dh = new Uint8Array(
        await subtle(
          () =>
            crypto.subtle.deriveBits({ name: skE.algorithm.name, public: pkR }, skE, this.Ndh << 3),
          this.name,
        ),
      )
      checkNotAllZeros(dh)

      const enc = await this.SerializePublicKey(pkE)
      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(
        this.kdf,
        this.suite_id,
        new Uint8Array(),
        encode('eae_prk'),
        dh,
      )
      const shared_secret = await LabeledExpand(
        this.kdf,
        this.suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        this.Nsecret,
      )
      return { shared_secret, enc }
    },
    async Decap(this: DHKEM, enc, skR, pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      assertCryptoKey(skR)
      if (pkR) {
        assertKeyAlgorithm(pkR, this.algorithm)
        assertCryptoKey(pkR)
      } else {
        pkR = await getPublicKey(this.name, skR, [])
      }

      const pkE = (await this.DeserializePublicKey(enc)) as CryptoKey

      // DH all-zero/point at infinity checks are performed
      // by WebCrypto's underlying implementations
      const dh = new Uint8Array(
        await subtle(
          () =>
            crypto.subtle.deriveBits({ name: skR.algorithm.name, public: pkE }, skR, this.Ndh << 3),
          this.name,
        ),
      )
      checkNotAllZeros(dh)

      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(
        this.kdf,
        this.suite_id,
        new Uint8Array(),
        encode('eae_prk'),
        dh,
      )
      const shared_secret = await LabeledExpand(
        this.kdf,
        this.suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        this.Nsecret,
      )
      return shared_secret
    },
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM Helper
// ============================================================================

async function createKeyPairFromPrivateKey(
  DHKEM: DHKEM,
  key: Uint8Array,
  extractable: boolean,
): Promise<CryptoKeyPair> {
  let privateKey: CryptoKey
  let publicKey: CryptoKey
  // @ts-expect-error
  if (!extractable && typeof crypto.subtle.getPublicKey !== 'function') {
    privateKey = (await DHKEM.DeserializePrivateKey(key, true)) as CryptoKey
    publicKey = await getPublicKey(DHKEM.name, privateKey, [])
    privateKey = (await DHKEM.DeserializePrivateKey(key, false)) as CryptoKey
  } else {
    privateKey = (await DHKEM.DeserializePrivateKey(key, extractable)) as CryptoKey
    publicKey = await getPublicKey(DHKEM.name, privateKey, [])
  }
  return { privateKey, publicKey }
}

async function CurveKeyFromD(
  name: string,
  Nsk: number,
  template: Uint8Array,
  algorithm: KeyAlgorithm,
  key: Uint8Array,
  extractable: boolean,
) {
  const tmpl = slice(template)
  const pkcs8 = new Uint8Array(Nsk + tmpl.byteLength)
  pkcs8.set(tmpl)
  pkcs8.set(key, tmpl.byteLength)
  return await subtle(
    () => crypto.subtle.importKey('pkcs8', pkcs8, algorithm, extractable, ['deriveBits']),
    name,
  )
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM NIST Curve Implementations
// ============================================================================

interface ECPoint {
  x: bigint
  y: bigint
}

// Modular inverse using Extended Euclidean Algorithm
function modInverse(a: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m
  let [t, newT] = [0n, 1n]
  let [r, newR] = [m, a]

  while (newR !== 0n) {
    const quotient = r / newR
    ;[t, newT] = [newT, t - quotient * newT]
    ;[r, newR] = [newR, r - quotient * newR]
  }

  if (r > 1n) throw new Error('a is not invertible')
  if (t < 0n) t = t + m
  return t
}

// Point doubling: 2P
function pointDouble(p: ECPoint, prime: bigint, a: bigint): ECPoint {
  const { x, y } = p

  // Slope: s = (3x² + a) / (2y) mod prime
  const numerator = (((3n * x * x) % prime) + a) % prime
  const denominator = (2n * y) % prime
  const s = (numerator * modInverse(denominator, prime)) % prime

  // x₃ = s² - 2x mod prime
  const x3 = (((s * s) % prime) - ((2n * x) % prime) + prime) % prime

  // y₃ = s(x - x₃) - y mod prime
  const y3 = (((s * ((x - x3 + prime) % prime)) % prime) - y + prime) % prime

  return { x: x3, y: y3 }
}

// Point addition: P + Q
function pointAdd(p: ECPoint, q: ECPoint, prime: bigint, a: bigint): ECPoint {
  if (p.x === q.x && p.y === q.y) {
    return pointDouble(p, prime, a)
  }

  const { x: x1, y: y1 } = p
  const { x: x2, y: y2 } = q

  // Check for P + (-P) = point at infinity case
  // This should not occur in normal ECDH operations, but guards against invalid inputs
  if (p.x === q.x) {
    throw new Error('Point addition resulted in point at infinity')
  }

  // Slope: s = (y₂ - y₁) / (x₂ - x₁) mod prime
  const numerator = (((y2 - y1) % prime) + prime) % prime
  const denominator = (((x2 - x1) % prime) + prime) % prime
  const s = (numerator * modInverse(denominator, prime)) % prime

  // x₃ = s² - x₁ - x₂ mod prime
  const x3 = (((s * s) % prime) - x1 - x2 + prime + prime) % prime

  // y₃ = s(x₁ - x₃) - y₁ mod prime
  const y3 = (((s * ((x1 - x3 + prime) % prime)) % prime) - y1 + prime) % prime

  return { x: x3, y: y3 }
}

// Scalar multiplication using double-and-add algorithm: k * G
function scalarMult(k: bigint, G: ECPoint, prime: bigint, a: bigint, order: bigint): ECPoint {
  if (k === 0n || k >= order) {
    throw new Error('Invalid scalar')
  }

  let result: ECPoint | null = null
  let addend = G
  let scalar = k

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = result === null ? addend : pointAdd(result, addend, prime, a)
    }
    addend = pointDouble(addend, prime, a)
    scalar = scalar >> 1n
  }

  if (result === null) throw new Error('Invalid result')
  return result
}

interface NistCurveConfig {
  order: bigint
  bitmask: number
  prime: bigint
  Gx: bigint
  Gy: bigint
  algorithm: EcKeyAlgorithm
  Npk: number
  Nsk: number
}

// Helper function to compute public key and create JWK for NIST curves
function getPrivateJwkNist(DHKEM: NistCurveConfig, d: bigint): JsonWebKey {
  // Perform scalar multiplication: publicKey = d * G
  const G: ECPoint = { x: DHKEM.Gx, y: DHKEM.Gy }
  const publicPoint = scalarMult(d, G, DHKEM.prime, DHKEM.prime - 3n, DHKEM.order)

  const coordSize = (DHKEM.Npk - 1) / 2
  const xBytes = bigIntToUint8Array(publicPoint.x, coordSize)
  const yBytes = bigIntToUint8Array(publicPoint.y, coordSize)
  const dBytes = bigIntToUint8Array(d, DHKEM.Nsk)

  // Create JWK for private key import (browsers need x, y, d for private key import)
  return {
    kty: 'EC',
    crv: DHKEM.algorithm.namedCurve,
    x: toB64u(xBytes),
    y: toB64u(yBytes),
    d: toB64u(dBytes),
  }
}

async function DeserializePrivateKeyNist(
  this: DHKEM & NistCurveConfig,
  key: Uint8Array,
  extractable: boolean,
) {
  const d = OS2IP(key)
  const jwk = getPrivateJwkNist(this, d)

  const privateKey = await subtle(
    () => crypto.subtle.importKey('jwk', jwk, this.algorithm, extractable, ['deriveBits']),
    this.name,
  )

  return privateKey
}

async function DeriveKeyPairNist(
  this: DHKEM & NistCurveConfig,
  ikm: Uint8Array,
  extractable: boolean,
) {
  let sk = 0n
  let counter = 0
  let bytes: Uint8Array
  while (sk === 0n || sk >= this.order) {
    if (counter > 255) {
      throw new DeriveKeyPairError('Key derivation exceeded maximum iterations')
    }
    bytes = await DeriveCandidate(this, this.suite_id, ikm, counter)
    bytes[0] = bytes[0]! & this.bitmask
    sk = OS2IP(bytes)
    counter = counter + 1
  }

  return GetKeyPairNist(this, bytes!, extractable, this.name)
}

async function GetKeyPairNist(
  curveConfig: typeof P256 | typeof P384,
  sk: Uint8Array,
  extractable: boolean,
  name: string,
) {
  const jwk = getPrivateJwkNist(curveConfig, OS2IP(sk))

  const privateKey = await subtle(
    () => crypto.subtle.importKey('jwk', jwk, curveConfig.algorithm, extractable, ['deriveBits']),
    name,
  )

  delete jwk.d
  const publicKey = await subtle(
    () => crypto.subtle.importKey('jwk', jwk, curveConfig.algorithm, true, []),
    name,
  )

  return { privateKey, publicKey }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM X Curve Implementations
// ============================================================================

async function DeriveKeyPairX(this: DHKEM, ikm: Uint8Array, extractable: boolean) {
  const dkp_prk = await LabeledExtract(
    this.kdf,
    this.suite_id,
    new Uint8Array(),
    encode('dkp_prk'),
    ikm,
  )
  const sk = await LabeledExpand(
    this.kdf,
    this.suite_id,
    dkp_prk,
    encode('sk'),
    new Uint8Array(),
    this.Nsk,
  )
  return await createKeyPairFromPrivateKey(this, sk, extractable)
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM Suite Exports (P-256, P-384, P-521)
// ============================================================================

const P256: NistCurveConfig = {
  algorithm: { name: 'ECDH', namedCurve: 'P-256' },
  Npk: 65,
  Nsk: 32,
  order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  bitmask: 0xff,
  prime: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
}

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-256 curve and HKDF-SHA256.
 *
 * A Diffie-Hellman based KEM using the NIST P-256 elliptic curve (also known as secp256r1) with
 * HKDF-SHA256 for key derivation.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ECDH with P-256 curve
 * - HMAC with SHA-256 (for HKDF)
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_DHKEM_P256_HKDF_SHA256: KEMFactory = function (): DHKEM & NistCurveConfig {
  const id = 0x0010
  const name = 'DHKEM(P-256, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 32,
    Nenc: 65,
    Ndh: 32,
    ...P256,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

const P384: NistCurveConfig = {
  algorithm: { name: 'ECDH', namedCurve: 'P-384' },
  Npk: 97,
  Nsk: 48,
  order:
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
  bitmask: 0xff,
  prime:
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  Gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  Gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
}

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-384 curve and HKDF-SHA384.
 *
 * A Diffie-Hellman based KEM using the NIST P-384 elliptic curve (also known as secp384r1) with
 * HKDF-SHA384 for key derivation.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ECDH with P-384 curve
 * - HMAC with SHA-384 (for HKDF)
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_DHKEM_P384_HKDF_SHA384: KEMFactory = function (): DHKEM & NistCurveConfig {
  const id = 0x0011
  const name = 'DHKEM(P-384, HKDF-SHA384)'
  const kdf = KDF_HKDF_SHA384()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 48,
    Nenc: 97,
    Ndh: 48,
    ...P384,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

const P521: NistCurveConfig = {
  Npk: 133,
  Nsk: 66,
  algorithm: { name: 'ECDH', namedCurve: 'P-521' },
  order:
    0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
  bitmask: 0x01,
  prime:
    0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  Gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
  Gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
}

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-521 curve and HKDF-SHA512.
 *
 * A Diffie-Hellman based KEM using the NIST P-521 elliptic curve (also known as secp521r1) with
 * HKDF-SHA512 for key derivation.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ECDH with P-521 curve
 * - HMAC with SHA-512 (for HKDF)
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_DHKEM_P521_HKDF_SHA512: KEMFactory = function (): DHKEM & NistCurveConfig {
  const id = 0x0012
  const name = 'DHKEM(P-521, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 64,
    Nenc: 133,
    Ndh: 66,
    ...P521,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - DHKEM Suite Exports (X25519, X448)
// ============================================================================

/**
 * Diffie-Hellman Key Encapsulation Mechanism using Curve25519 and HKDF-SHA256.
 *
 * A Diffie-Hellman based KEM using the X25519 elliptic curve (Curve25519 for ECDH) with HKDF-SHA256
 * for key derivation.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - X25519 key agreement
 * - HMAC with SHA-256 (for HKDF)
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_DHKEM_X25519_HKDF_SHA256: KEMFactory = function (): DHKEM & { pkcs8: Uint8Array } {
  const id = 0x0020
  const name = 'DHKEM(X25519, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 32,
    Nenc: 32,
    Npk: 32,
    Nsk: 32,
    Ndh: 32,
    algorithm: { name: 'X25519' },
    pkcs8: Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20), // prettier-ignore
    DeriveKeyPair: DeriveKeyPairX,
    async DeserializePrivateKey(key, extractable) {
      return await CurveKeyFromD(name, this.Nsk, this.pkcs8, this.algorithm, key, extractable)
    },
    ...DHKEM_SHARED(),
  }
}

/**
 * Diffie-Hellman Key Encapsulation Mechanism using Curve448 and HKDF-SHA512.
 *
 * A Diffie-Hellman based KEM using the X448 elliptic curve (Curve448 for ECDH) with HKDF-SHA512 for
 * key derivation.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - X448 key agreement
 * - HMAC with SHA-512 (for HKDF)
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_DHKEM_X448_HKDF_SHA512: KEMFactory = function (): DHKEM & { pkcs8: Uint8Array } {
  const id = 0x0021
  const name = 'DHKEM(X448, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 64,
    Nenc: 56,
    Npk: 56,
    Nsk: 56,
    Ndh: 56,
    algorithm: { name: 'X448' },
    pkcs8: Uint8Array.of(0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38), // prettier-ignore
    DeriveKeyPair: DeriveKeyPairX,
    async DeserializePrivateKey(key, extractable) {
      return await CurveKeyFromD(name, this.Nsk, this.pkcs8, this.algorithm, key, extractable)
    },
    ...DHKEM_SHARED(),
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - ML-KEM Types and Implementation
// ============================================================================

interface MLKEM extends KEM {
  readonly suite_id: Uint8Array
  readonly algorithm: Readonly<KeyAlgorithm>
  readonly kdf: KDF
}

function MLKEM_SHARED(): KEM_BASE {
  return {
    async DeriveKeyPair(this: MLKEM, ikm, extractable) {
      const dk = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        this.Nsk,
      )

      const privateKey = (await this.DeserializePrivateKey(dk, extractable)) as CryptoKey
      // @ts-expect-error
      const usages: KeyUsage[] = ['encapsulateBits']
      const publicKey = await getPublicKey(this.name, privateKey, usages)

      return { privateKey, publicKey }
    },
    async GenerateKeyPair(this: MLKEM, extractable) {
      // @ts-expect-error
      const usages: KeyUsage[] = ['encapsulateBits', 'decapsulateBits']
      return (await subtle(
        () => crypto.subtle.generateKey(this.algorithm, extractable, usages),
        this.name,
      )) as CryptoKeyPair
    },
    async SerializePublicKey(this: MLKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-public'
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey(format, key), this.name))
    },
    async DeserializePublicKey(this: MLKEM, _key) {
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-public'
      // @ts-expect-error
      const usages: KeyUsage[] = ['encapsulateBits']
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey(format, key, this.algorithm, true, usages),
        this.name,
      )
    },
    async SerializePrivateKey(this: MLKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-seed'
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey(format, key), this.name))
    },
    async DeserializePrivateKey(this: MLKEM, _key, extractable) {
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-seed'
      // @ts-expect-error
      const usages: KeyUsage[] = ['decapsulateBits']
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey(format, key, this.algorithm, extractable, usages),
        this.name,
      )
    },
    async Encap(this: MLKEM, pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)

      const { sharedKey, ciphertext } = (await subtle(
        () =>
          // @ts-expect-error
          crypto.subtle.encapsulateBits(this.algorithm, pkR),
        this.name,
      )) as { sharedKey: ArrayBuffer; ciphertext: ArrayBuffer }

      return { shared_secret: new Uint8Array(sharedKey), enc: new Uint8Array(ciphertext) }
    },
    async Decap(this: MLKEM, _enc, skR, _pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      const enc = ab(_enc)
      return new Uint8Array(
        await subtle(
          () =>
            // @ts-expect-error
            crypto.subtle.decapsulateBits(this.algorithm, skR, enc),
          this.name,
        ),
      )
    },
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - ML-KEM Suite Exports
// ============================================================================

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-512).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-512 key encapsulation
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient for key derivation
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_ML_KEM_512: KEMFactory = function (): MLKEM {
  const id = 0x0040
  const name = 'ML-KEM-512'
  const kdf = KDF_SHAKE256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 768,
    Npk: 800,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-512' },
    kdf,
    ...MLKEM_SHARED(),
  }
}

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-768).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-768 key encapsulation
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient for key derivation
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_ML_KEM_768: KEMFactory = function (): MLKEM {
  const id = 0x0041
  const name = 'ML-KEM-768'
  const kdf = KDF_SHAKE256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1088,
    Npk: 1184,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-768' },
    kdf,
    ...MLKEM_SHARED(),
  }
}

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-1024).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-1024 key encapsulation
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient for key derivation
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_ML_KEM_1024: KEMFactory = function (): MLKEM {
  const id = 0x0042
  const name = 'ML-KEM-1024'
  const kdf = KDF_SHAKE256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1568,
    Npk: 1568,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-1024' },
    kdf,
    ...MLKEM_SHARED(),
  }
}

interface WebCryptoAEAD extends AEAD {
  readonly algorithm: string
  readonly keyFormat: Exclude<KeyFormat, 'jwk'>
}

type AEAD_BASE = Pick<AEAD, 'Seal' | 'Open'>

function AEAD_SHARED(): AEAD_BASE {
  return {
    async Seal(this: WebCryptoAEAD, _key, _nonce, _aad, _pt) {
      const nonce = ab(_nonce)
      const aad = ab(_aad)
      const key = ab(_key)
      const pt = ab(_pt)
      return new Uint8Array(
        await subtle(
          async () =>
            crypto.subtle.encrypt(
              { name: this.algorithm, iv: nonce, additionalData: aad },
              await crypto.subtle.importKey(this.keyFormat, key, this.algorithm, false, [
                'encrypt',
              ]),
              pt,
            ),
          this.name,
        ),
      )
    },
    async Open(this: WebCryptoAEAD, _key, _nonce, _aad, _ct) {
      const nonce = ab(_nonce)
      const aad = ab(_aad)
      const key = ab(_key)
      const ct = ab(_ct)
      return new Uint8Array(
        await subtle(
          async () =>
            crypto.subtle.decrypt(
              { name: this.algorithm, iv: nonce, additionalData: aad },
              await crypto.subtle.importKey(this.keyFormat, key, this.algorithm, false, [
                'decrypt',
              ]),
              ct,
            ),
          this.name,
        ),
      )
    },
  }
}

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data) - Suite Exports
// ============================================================================

/**
 * AES-128-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 128-bit keys.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - AES-GCM encryption and decryption
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group AEAD Algorithms
 */
export const AEAD_AES_128_GCM: AEADFactory = function (): WebCryptoAEAD {
  return {
    id: 0x0001,
    type: 'AEAD',
    name: 'AES-128-GCM',
    Nk: 16,
    Nn: 12,
    Nt: 16,
    algorithm: 'AES-GCM',
    keyFormat: 'raw',
    ...AEAD_SHARED(),
  }
}

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 256-bit keys.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - AES-GCM encryption and decryption
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group AEAD Algorithms
 */
export const AEAD_AES_256_GCM: AEADFactory = function (): WebCryptoAEAD {
  return {
    id: 0x0002,
    type: 'AEAD',
    name: 'AES-256-GCM',
    Nk: 32,
    Nn: 12,
    Nt: 16,
    algorithm: 'AES-GCM',
    keyFormat: 'raw',
    ...AEAD_SHARED(),
  }
}

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses ChaCha20 stream cipher with Poly1305 MAC.
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ChaCha20-Poly1305 encryption and decryption
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group AEAD Algorithms
 */
export const AEAD_ChaCha20Poly1305: AEADFactory = function AEAD_ChaCha20Poly1305(): WebCryptoAEAD {
  return {
    id: 0x0003,
    type: 'AEAD',
    name: 'ChaCha20Poly1305',
    Nk: 32,
    Nn: 12,
    Nt: 16,
    algorithm: 'ChaCha20-Poly1305',
    // @ts-expect-error
    keyFormat: 'raw-secret',
    ...AEAD_SHARED(),
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - Hybrid KEM Types and Implementation
// ============================================================================

/* c8 ignore next 5 */
const InvalidInvocation = (_: typeof priv) => {
  if (_ !== priv) {
    throw new Error('invalid invocation')
  }
}
const priv = Symbol()
class HybridKey implements Key {
  #algorithm: KeyAlgorithm

  #type: 'public' | 'private'

  #extractable: boolean

  #t: CryptoKey

  #pq: CryptoKey

  #seed?: Uint8Array | undefined

  #publicKey?: HybridKey | undefined

  static #isValid(key: HybridKey): boolean {
    return key.#algorithm !== undefined
  }

  static validate(key: unknown, extractable?: boolean): asserts key is HybridKey {
    try {
      if (!HybridKey.#isValid(key as HybridKey)) {
        throw new TypeError('unexpected key constructor')
      }
    } catch {
      throw new TypeError('unexpected key constructor')
    }
    if (extractable && !(key as HybridKey).extractable) {
      throw new TypeError('key must be extractable')
    }
  }

  constructor(
    _: typeof priv,
    algorithm: KeyAlgorithm,
    type: 'public' | 'private',
    extractable: boolean,
    pq: CryptoKey,
    t: CryptoKey,
    seed?: Uint8Array,
    publicKey?: HybridKey,
  ) {
    InvalidInvocation(_)
    this.#algorithm = algorithm
    this.#type = type
    this.#extractable = extractable
    this.#pq = pq
    this.#t = t
    this.#seed = seed
    this.#publicKey = publicKey
  }

  get algorithm() {
    return { name: this.#algorithm.name }
  }

  get extractable() {
    return this.#extractable
  }

  get type() {
    return this.#type
  }

  getPublicKey(_: typeof priv) {
    InvalidInvocation(_)
    return this.#publicKey
  }

  getSeed(_: typeof priv) {
    InvalidInvocation(_)
    return slice(this.#seed!)
  }

  getT(_: typeof priv) {
    InvalidInvocation(_)
    return this.#t
  }

  getPq(_: typeof priv) {
    InvalidInvocation(_)
    return this.#pq
  }
}

function split(N1: number, N2: number, x: Uint8Array): [Uint8Array, Uint8Array] {
  if (x.byteLength !== N1 + N2) {
    throw new Error('x.byteLength !== N1 + N2')
  }

  const x1 = slice(x, 0, N1)
  const x2 = slice(x, -N2)

  return [x1, x2]
}

function RandomScalarNist(t: HybridKEM['t'], seed: Uint8Array): Uint8Array {
  let sk_bigint = 0n
  let start = 0
  let end = t.Nscalar!
  sk_bigint = OS2IP(slice(seed, start, end))

  while (sk_bigint === 0n || sk_bigint >= t.order!) {
    start = end
    end = end + t.Nscalar!
    if (end > seed.byteLength) {
      throw new DeriveKeyPairError('Rejection sampling failed')
    }
    sk_bigint = OS2IP(slice(seed, start, end))
  }
  return bigIntToUint8Array(sk_bigint, t.Nscalar!)
}

async function expandDecapsKeyG(PQTKEM: HybridKEM, _seed: Uint8Array) {
  const Nout = PQTKEM.pq.Nseed + PQTKEM.t.Nseed
  // @ts-expect-error
  const algorithm: CShakeParams = { name: 'cSHAKE256', length: Nout << 3 }
  const seed = ab(_seed)
  const seed_full = await subtle(() => crypto.subtle.digest(algorithm, seed), PQTKEM.name)

  const [_seed_PQ, seed_T] = split(PQTKEM.pq.Nseed, PQTKEM.t.Nseed, new Uint8Array(seed_full))
  const seed_PQ = ab(_seed_PQ)

  // @ts-expect-error
  const format: Exclude<KeyFormat, 'jwk'> = 'raw-seed'
  // @ts-expect-error
  const usages: [KeyUsage, KeyUsage] = ['decapsulateBits', 'encapsulateBits']
  const dk_PQ = await subtle(
    () => crypto.subtle.importKey(format, seed_PQ, PQTKEM.pq.algorithm, true, [usages[0]]),
    PQTKEM.name,
  )
  const ek_PQ = await getPublicKey(PQTKEM.name, dk_PQ, [usages[1]])

  const sk = PQTKEM.t.RandomScalar?.(seed_T) ?? seed_T
  const { privateKey: dk_T, publicKey: ek_T } = await PQTKEM.t.GetKeyPair(sk)

  return { ek_PQ, ek_T, dk_PQ, dk_T }
}

async function C2PRICombiner(
  PQTKEM: HybridKEM,
  ss_PQ: Uint8Array,
  ss_T: Uint8Array,
  ct_T: Uint8Array,
  _ek_T: CryptoKey,
  label: Uint8Array,
): Promise<Uint8Array> {
  const ek_T = new Uint8Array(
    await subtle(() => crypto.subtle.exportKey('raw', _ek_T), PQTKEM.name),
  )
  const data = ab(concat(ss_PQ, ss_T, ct_T, ek_T, label))
  return new Uint8Array(await subtle(() => crypto.subtle.digest('SHA3-256', data), PQTKEM.name))
}

async function prepareEncapsG(
  PQTKEM: HybridKEM,
  ek_PQ: CryptoKey,
  ek_T: CryptoKey,
): Promise<[Uint8Array, Uint8Array, Uint8Array, Uint8Array]> {
  const res = (await subtle(
    () =>
      // @ts-expect-error
      crypto.subtle.encapsulateBits(PQTKEM.pq.algorithm, ek_PQ),
    PQTKEM.name,
  )) as { sharedKey: ArrayBuffer; ciphertext: ArrayBuffer }
  const ss_PQ = new Uint8Array(res.sharedKey)
  const ct_PQ = new Uint8Array(res.ciphertext)

  const { privateKey: sk_E, publicKey } = (await subtle(
    () => crypto.subtle.generateKey(PQTKEM.t.algorithm, true, ['deriveBits']),
    PQTKEM.name,
  )) as CryptoKeyPair
  const ct_T = new Uint8Array(
    await subtle(() => crypto.subtle.exportKey('raw', publicKey), PQTKEM.name),
  )

  const ss_T = new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.deriveBits(
          { name: PQTKEM.t.algorithm.name, public: ek_T },
          sk_E,
          PQTKEM.t.Nss << 3,
        ),
      PQTKEM.name,
    ),
  )
  checkNotAllZeros(ss_T)

  return [ss_PQ, ss_T, ct_PQ, ct_T]
}

async function prepareDecapsG(
  PQTKEM: HybridKEM,
  dk_PQ: CryptoKey,
  dk_T: CryptoKey,
  ct_PQ: Uint8Array,
  _ct_T: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
  const ss_PQ = new Uint8Array(
    await subtle(
      () =>
        // @ts-expect-error
        crypto.subtle.decapsulateBits(PQTKEM.pq.algorithm, dk_PQ, ct_PQ),
      PQTKEM.name,
    ),
  )

  const ct_T = ab(_ct_T)
  const pub = await subtle(
    () => crypto.subtle.importKey('raw', ct_T, PQTKEM.t.algorithm, true, []),
    PQTKEM.name,
  )

  const ss_T = new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.deriveBits(
          { name: PQTKEM.t.algorithm.name, public: pub },
          dk_T,
          PQTKEM.t.Nss << 3,
        ),
      PQTKEM.name,
    ),
  )
  checkNotAllZeros(ss_T)

  return [ss_PQ, ss_T]
}

interface HybridKEM extends KEM {
  readonly suite_id: Uint8Array
  readonly kdf: KDF
  readonly algorithm: KeyAlgorithm
  readonly label: Uint8Array
  readonly pq: {
    readonly algorithm: KeyAlgorithm
    readonly Nseed: number
    readonly Npk: number
    readonly Nct: number
  }
  readonly t: {
    readonly algorithm: KeyAlgorithm | EcKeyAlgorithm
    readonly Nseed: number
    readonly Nct: number
    readonly Nss: number
    readonly Npk: number
    readonly Nsk: number
    readonly Nscalar?: number
    readonly GetKeyPair: (
      this: HybridKEM['t'],
      sk: Uint8Array,
    ) => Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }>
    readonly order?: bigint
    readonly RandomScalar?: (this: HybridKEM['t'], seed: Uint8Array) => Uint8Array
  }
}

function PQTKEM_SHARED(): KEM_BASE {
  Object.freeze(HybridKey.prototype)
  return {
    async DeriveKeyPair(this: HybridKEM, ikm: Uint8Array, extractable) {
      const seed = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        32,
      )

      const { ek_PQ, ek_T, dk_PQ, dk_T } = await expandDecapsKeyG(this, seed)

      const publicKey = new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
      const privateKey = new HybridKey(
        priv,
        this.algorithm,
        'private',
        extractable,
        dk_PQ,
        dk_T,
        seed,
        publicKey,
      )

      return { privateKey, publicKey }
    },
    async GenerateKeyPair(this: HybridKEM, extractable) {
      return await this.DeriveKeyPair(crypto.getRandomValues(new Uint8Array(32)), extractable)
    },
    async SerializePublicKey(this: HybridKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      HybridKey.validate(key, true)
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-public'
      const ek_PQ = new Uint8Array(
        await subtle(() => crypto.subtle.exportKey(format, key.getPq(priv)), this.name),
      )
      const ek_T = new Uint8Array(
        await subtle(() => crypto.subtle.exportKey('raw', key.getT(priv)), this.name),
      )

      return concat(ek_PQ, ek_T)
    },
    async DeserializePublicKey(this: HybridKEM, key) {
      // @ts-expect-error
      const format: Exclude<KeyFormat, 'jwk'> = 'raw-public'
      // @ts-expect-error
      const usages: KeyUsage[] = ['encapsulateBits']
      const pubPq = ab(key.subarray(0, this.pq.Npk))
      const pubT = ab(key.subarray(this.pq.Npk))
      const [ek_PQ, ek_T] = await Promise.all([
        subtle(
          () => crypto.subtle.importKey(format, pubPq, this.pq.algorithm, true, usages),
          this.name,
        ),
        subtle(() => crypto.subtle.importKey('raw', pubT, this.t.algorithm, true, []), this.name),
      ])

      return new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
    },
    async SerializePrivateKey(this: HybridKEM, key) {
      assertKeyAlgorithm(key, this.algorithm)
      HybridKey.validate(key, true)

      return key.getSeed(priv)
    },
    async DeserializePrivateKey(this: HybridKEM, key, extractable) {
      const { ek_PQ, ek_T, dk_PQ, dk_T } = await expandDecapsKeyG(this, key)
      const publicKey = new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
      const privateKey = new HybridKey(
        priv,
        this.algorithm,
        'private',
        extractable,
        dk_PQ,
        dk_T,
        slice(key),
        publicKey,
      )

      return privateKey
    },
    async Encap(this: HybridKEM, pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      HybridKey.validate(pkR)

      const ek_PQ = pkR.getPq(priv)
      const ek_T = pkR.getT(priv)
      const [ss_PQ, ss_T, ct_PQ, ct_T] = await prepareEncapsG(this, ek_PQ, ek_T)
      const ss_H = await C2PRICombiner(this, ss_PQ, ss_T, ct_T, ek_T, this.label)
      const ct_H = concat(ct_PQ, ct_T)

      return { shared_secret: ss_H, enc: ct_H }
    },
    async Decap(this: HybridKEM, enc, skR, pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      HybridKey.validate(skR)

      if (pkR) {
        assertKeyAlgorithm(pkR, this.algorithm)
        HybridKey.validate(pkR)
      }

      const [ct_PQ, ct_T] = split(this.pq.Nct, this.t.Nct, enc)
      const ek = pkR ?? skR.getPublicKey(priv)!
      const ek_T = ek.getT(priv)
      const dk_PQ = skR.getPq(priv)
      const dk_T = skR.getT(priv)
      const [ss_PQ, ss_T] = await prepareDecapsG(this, dk_PQ, dk_T, ct_PQ, ct_T)
      const ss_H = await C2PRICombiner(this, ss_PQ, ss_T, ct_T, ek_T, this.label)

      return ss_H
    },
  }
}

// ============================================================================
// KEM (Key Encapsulation Mechanism) - Hybrid KEM Suite Exports
// ============================================================================

/**
 * Hybrid KEM combining ML-KEM-768 with X25519 (MLKEM768-X25519 aka X-Wing).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-768 key encapsulation
 * - X25519 key agreement
 * - SHA3-256 digest
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_MLKEM768_X25519: KEMFactory = function (): HybridKEM {
  const id = 0x647a
  const name = 'MLKEM768-X25519'
  const kdf = KDF_SHAKE256()
  const pkcs8 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20); // prettier-ignore
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1120,
    Npk: 1216,
    Nsk: 32,
    algorithm: { name: 'MLKEM768-X25519' },
    pq: { algorithm: { name: 'ML-KEM-768' }, Nseed: 64, Npk: 1184, Nct: 1088 },
    t: {
      algorithm: { name: 'X25519' },
      Nseed: 32,
      Npk: 32,
      Nss: 32,
      Nsk: 32,
      Nct: 32,
      async GetKeyPair(sk) {
        const privateKey = await CurveKeyFromD(name, this.Nsk, pkcs8, this.algorithm, sk, true)
        const publicKey = await getPublicKey(name, privateKey, [])

        return { privateKey, publicKey }
      },
    },
    label: Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c), // prettier-ignore
    ...PQTKEM_SHARED(),
  }
}

/**
 * Hybrid KEM combining ML-KEM-768 with P-256 (MLKEM768-P256).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-768 key encapsulation
 * - ECDH with P-256 curve
 * - SHA3-256 digest
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_MLKEM768_P256: KEMFactory = function (): HybridKEM {
  const id = 0x0050
  const name = 'MLKEM768-P256'
  const kdf = KDF_SHAKE256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1153,
    Npk: 1249,
    Nsk: 32,
    algorithm: { name: 'MLKEM768-P256' },
    pq: { algorithm: { name: 'ML-KEM-768' }, Nseed: 64, Npk: 1184, Nct: 1088 },
    t: {
      ...P256,
      Nseed: 128,
      Nss: 32,
      Nct: 65,
      Nscalar: 32,
      order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
      },
      GetKeyPair(sk) {
        return GetKeyPairNist(P256, sk, true, name)
      },
    },
    label: Uint8Array.of(0x4d, 0x4c, 0x4b, 0x45, 0x4d, 0x37, 0x36, 0x38, 0x2d, 0x50, 0x32, 0x35, 0x36), // prettier-ignore
    ...PQTKEM_SHARED(),
  }
}

/**
 * Hybrid KEM combining ML-KEM-1024 with P-384 (MLKEM1024-P384).
 *
 * Depends on the following Web Cryptography algorithms being supported in the runtime:
 *
 * - ML-KEM-1024 key encapsulation
 * - ECDH with P-384 curve
 * - SHA3-256 digest
 * - SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion
 *
 * This is a factory function that must be passed to the {@link CipherSuite} constructor.
 *
 * > [!TIP]\
 * > An implementation of this algorithm not reliant on Web Cryptography is also exported by
 * > [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
 *
 * @group KEM Algorithms
 */
export const KEM_MLKEM1024_P384: KEMFactory = function (): HybridKEM {
  const id = 0x0051
  const name = 'MLKEM1024-P384'
  const kdf = KDF_SHAKE256()
  // @ts-expect-error: so that NotSupportedError messages from kdf's subtle() are accurate
  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1665,
    Npk: 1665,
    Nsk: 32,
    algorithm: { name: 'MLKEM1024-P384' },
    pq: { algorithm: { name: 'ML-KEM-1024' }, Nseed: 64, Npk: 1568, Nct: 1568 },
    t: {
      ...P384,
      Nseed: 48,
      Nss: 48,
      Nct: 97,
      Nscalar: 48,
      order:
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
      },
      GetKeyPair(sk) {
        return GetKeyPairNist(P384, sk, true, name)
      },
    },
    label: Uint8Array.of(0x4d, 0x4c, 0x4b, 0x45, 0x4d, 0x31, 0x30, 0x32, 0x34, 0x2d, 0x50, 0x33, 0x38, 0x34), // prettier-ignore
    ...PQTKEM_SHARED(),
  }
}
