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











































 * @group Core
 */
declare class SenderContext {
    #private;
    constructor(suite: Triple, mode: number, key: Uint8Array, base_nonce: Uint8Array, exporter_secret: Uint8Array);
    /** @returns The mode (0x00 = Base, 0x01 = PSK) for this context. */
    get mode(): number;
    /**
     * @returns The sequence number for this context's next {@link Seal}, initially zero, increments
     *   automatically with each successful {@link Seal}. The sequence number provides AEAD nonce
     *   uniqueness.
     */
    get seq(): number;
    /**
     * Encrypts plaintext with additional authenticated data. Each successful call automatically
     * increments the sequence number to ensure nonce uniqueness.
     *















     * @param plaintext - Plaintext to encrypt
     * @param aad - Additional authenticated data
     *
     * @returns A Promise that resolves to the ciphertext. The ciphertext is {@link Nt} bytes longer
     *   than the plaintext.
     */
    Seal(plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;
    /**
     * Exports a secret using a variable-length pseudorandom function (PRF).
     *
     * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
     *












     * @param exporterContext - Context for domain separation
     * @param length - Desired length of exported secret in bytes
     *
     * @returns A Promise that resolves to the exported secret.
     */
    Export(exporterContext: Uint8Array, length: number): Promise<Uint8Array>;
    /**
     * @returns The length in bytes of an authentication tag for the AEAD algorithm used by this
     *   context.
     */
    get Nt(): number;
}
export type { SenderContext };
/**
 * Context for decrypting multiple messages and exporting secrets on the recipient side.
 *
 * `RecipientContext` instance is obtained from {@link CipherSuite.SetupRecipient}.
 *












 * @group Core
 */
declare class RecipientContext {
    #private;
    constructor(suite: Triple, mode: number, key: Uint8Array, base_nonce: Uint8Array, exporter_secret: Uint8Array);
    /** @returns The mode (0x00 = Base, 0x01 = PSK) for this context. */
    get mode(): number;
    /**
     * @returns The sequence number for this context's next {@link Open}, initially zero, increments
     *   automatically with each successful {@link Open}. The sequence number provides AEAD nonce
     *   uniqueness.
     */
    get seq(): number;
    /**
     * Decrypts ciphertext with additional authenticated data.
     *
     * Applications must ensure that ciphertexts are presented to `Open` in the exact order they were
     * produced by the sender.
     *















     * @param ciphertext - Ciphertext to decrypt
     * @param aad - Additional authenticated data (must match sender's `aad`)
     *
     * @returns A Promise that resolves to the decrypted plaintext.
     */
    Open(ciphertext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;
    /**
     * Exports a secret using a variable-length pseudorandom function (PRF).
     *
     * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
     *












     * @param exporterContext - Context for domain separation
     * @param length - Desired length of exported secret in bytes
     *
     * @returns A Promise that resolves to the exported secret.
     */
    Export(exporterContext: Uint8Array, length: number): Promise<Uint8Array>;
}
export type { RecipientContext };
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
export declare class CipherSuite {
    #private;
    /**
     * Creates a new HPKE cipher suite by combining a Key Encapsulation Mechanism (KEM), Key
     * Derivation Function (KDF), and an Authenticated Encryption with Associated Data (AEAD)
     * algorithm.
     *
     * A cipher suite defines the complete cryptographic configuration for HPKE operations. The choice
     * of algorithms affects security properties, performance, and compatibility across different
     * platforms and runtimes.
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
    constructor(KEM: KEMFactory, KDF: KDFFactory, AEAD: AEADFactory);
    /**
     * Provides read-only access to this suite's KEM identifier, name, and other attributes.
     *
     * @returns An object with this suite's Key Encapsulation Mechanism (KEM) properties.
     */
    get KEM(): {
        /** The identifier of this suite's KEM */
        id: number;
        /** The name of this suite's KEM */
        name: string;
        /** The length in bytes of this suite's KEM produced shared secret */
        Nsecret: number;
        /** The length in bytes of this suite's KEM produced encapsulated key */
        Nenc: number;
        /** The length in bytes of this suite's KEM public key */
        Npk: number;
        /** The length in bytes of this suite's KEM private key */
        Nsk: number;
    };
    /**
     * Provides read-only access to this suite's KDF identifier, name, and other attributes.
     *
     * @returns An object with this suite's Key Derivation Function (KDF) properties.
     */
    get KDF(): {
        /** The identifier of this suite's KDF */
        id: number;
        /** The name of this suite's KDF */
        name: string;
        /**
         * When 1, this suite's KDF is a one-stage (Derive) KDF.
         *
         * When 2, this suite's KDF is a two-stage (Extract and Expand) KDF.
         */
        stages: 1 | 2;
        /**
         * For one-stage KDF: The security strength of this suite's KDF, in bytes.
         *
         * For two-stage KDF: The output size of this suite's KDF Extract() function in bytes.
         */
        Nh: number;
    };
    /**
     * Provides read-only access to this suite's AEAD identifier, name, and other attributes.
     *
     * @returns An object with this suite's Authenticated Encryption with Associated Data (AEAD)
     *   cipher properties.
     */
    get AEAD(): {
        /** The identifier of this suite's AEAD */
        id: number;
        /** The name of this suite's AEAD */
        name: string;
        /** The length in bytes of a key for this suite's AEAD */
        Nk: number;
        /** The length in bytes of a nonce for this suite's AEAD */
        Nn: number;
        /** The length in bytes of an authentication tag for this suite's AEAD */
        Nt: number;
    };
    /**
     * Generates a random key pair for this CipherSuite. By default, private keys are generated as
     * non-extractable (their value cannot be exported).
     *
     * @category Key Management







     * @param extractable - Whether the generated key pair's private key should be extractable (e.g.
     *   by {@link SerializePrivateKey}) (default: false)
     *
     * @returns A Promise that resolves to a generated key pair.
     */
    GenerateKeyPair(extractable?: boolean): Promise<KeyPair>;
    /**
     * Deterministically derives a key pair for this CipherSuite from input keying material. By
     * default, private keys are derived as non-extractable (their value cannot be exported).
     *
     * An `ikm` input MUST NOT be reused elsewhere, particularly not with `DeriveKeyPair()` of a
     * different KEM.
     *
     * @category Key Management








     * @param ikm - Input keying material (must be at least {@link CipherSuite.KEM Nsk} bytes)
     * @param extractable - Whether the derived key pair's private key should be extractable (e.g. by
     *   {@link SerializePrivateKey}) (default: false)
     *
     * @returns A Promise that resolves to the derived key pair.
     */
    DeriveKeyPair(ikm: Uint8Array, extractable?: boolean): Promise<KeyPair>;
    /**
     * Serializes an extractable private key to bytes.
     *
     * @category Key Management








     * @param privateKey - Private key to serialize
     *
     * @returns A Promise that resolves to the serialized private key.
     */
    SerializePrivateKey(privateKey: Key): Promise<Uint8Array>;
    /**
     * Serializes a public key to bytes.
     *
     * @category Key Management








     * @param publicKey - Public key to serialize
     *
     * @returns A Promise that resolves to the serialized public key.
     */
    SerializePublicKey(publicKey: Key): Promise<Uint8Array>;
    /**
     * Deserializes a private key from bytes. By default, private keys are deserialized as
     * non-extractable (their value cannot be exported).
     *
     * @category Key Management








     * @param privateKey - Serialized private key
     * @param extractable - Whether the deserialized private key should be extractable (e.g. by
     *   {@link SerializePrivateKey}) (default: false)
     *
     * @returns A Promise that resolves to the deserialized private key.
     */
    DeserializePrivateKey(privateKey: Uint8Array, extractable?: boolean): Promise<Key>;
    /**
     * Deserializes a public key from bytes. Public keys are always deserialized as extractable (their
     * value can be exported, e.g. by {@link SerializePublicKey}).
     *
     * @category Key Management








     * @param publicKey - Serialized public key
     *
     * @returns A Promise that resolves to the deserialized public key.
     */
    DeserializePublicKey(publicKey: Uint8Array): Promise<Key>;
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











     * @param publicKey - Recipient's public key
     * @param plaintext - Plaintext to encrypt
     * @param options - Options
     * @param options.aad - Additional authenticated data passed to the AEAD
     * @param options.info - Application-supplied information
     * @param options.psk - Pre-shared key (for PSK modes)
     * @param options.pskId - Pre-shared key identifier (for PSK modes)
     *
     * @returns A Promise that resolves to an object containing the encapsulated key and ciphertext.
     *   The ciphertext is {@link CipherSuite.AEAD Nt} bytes longer than the plaintext. The
     *   encapsulated key is {@link CipherSuite.KEM Nenc} bytes.
     */
    Seal(publicKey: Key, plaintext: Uint8Array, options?: {
        aad?: Uint8Array;
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<{
        encapsulatedKey: Uint8Array;
        ciphertext: Uint8Array;
    }>;
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













     * @param privateKey - Recipient's private key or key pair
     * @param encapsulatedKey - Encapsulated key from the sender
     * @param ciphertext - Ciphertext to decrypt
     * @param options - Options
     * @param options.aad - Additional authenticated data (must match sender's `aad`)
     * @param options.info - Application-supplied information (must match sender's `info`)
     * @param options.psk - Pre-shared key (for PSK mode, must match sender's `psk`)
     * @param options.pskId - Pre-shared key identifier (for PSK mode, must match sender's `pskId`)
     *
     * @returns A Promise that resolves to the decrypted plaintext.
     */
    Open(privateKey: Key | KeyPair, encapsulatedKey: Uint8Array, ciphertext: Uint8Array, options?: {
        aad?: Uint8Array;
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Single-shot API for deriving a secret known only to sender and recipient.
     *
     * It combines context setup and secret export in one call.
     *
     * The exported secret is indistinguishable from a uniformly random bitstring of equal length.
     *
     * @category Single-Shot APIs















     * @param publicKey - Recipient's public key
     * @param exporterContext - Context of the export operation
     * @param length - Desired length of exported secret in bytes
     * @param options - Options
     * @param options.info - Application-supplied information
     * @param options.psk - Pre-shared key (for PSK modes)
     * @param options.pskId - Pre-shared key identifier (for PSK modes)
     *
     * @returns A Promise that resolves to an object containing the encapsulated key and the exported
     *   secret.
     */
    SendExport(publicKey: Key, exporterContext: Uint8Array, length: number, options?: {
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<{
        encapsulatedKey: Uint8Array;
        exportedSecret: Uint8Array;
    }>;
    /**
     * Single-shot API for receiving an exported secret.
     *
     * It combines context setup and secret export in one call.
     *
     * @category Single-Shot APIs



















     * @param privateKey - Recipient's private key or key pair
     * @param encapsulatedKey - Encapsulated key from the sender
     * @param exporterContext - Context of the export operation (must match sender's
     *   `exporterContext`)
     * @param length - Desired length of exported secret in bytes (must match sender's `L`)
     * @param options - Options
     * @param options.info - Application-supplied information (must match sender's `info`)
     * @param options.psk - Pre-shared key (for PSK mode, must match sender's `psk`)
     * @param options.pskId - Pre-shared key identifier (for PSK mode, must match sender's `pskId`)
     *
     * @returns A Promise that resolves to the exported secret.
     */
    ReceiveExport(privateKey: Key | KeyPair, encapsulatedKey: Uint8Array, exporterContext: Uint8Array, length: number, options?: {
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<Uint8Array>;
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


















     * @param publicKey - Recipient's public key
     * @param options - Options
     * @param options.info - Application-supplied information
     * @param options.psk - Pre-shared key (for PSK modes)
     * @param options.pskId - Pre-shared key identifier (for PSK modes)
     *
     * @returns A Promise that resolves to an object containing the encapsulated key and the sender
     *   context (`ctx`). The encapsulated key is {@link CipherSuite.KEM Nenc} bytes.
     */
    SetupSender(publicKey: Key, options?: {
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<{
        encapsulatedKey: Uint8Array;
        ctx: SenderContext;
    }>;
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
























     * @param privateKey - Recipient's private key or key pair
     * @param encapsulatedKey - Encapsulated key from the sender
     * @param options - Options
     * @param options.info - Application-supplied information (must match sender's `info`)
     * @param options.psk - Pre-shared key (for PSK mode, must match sender's `psk`)
     * @param options.pskId - Pre-shared key identifier (for PSK mode, must match sender's `pskId`)
     *
     * @returns A Promise that resolves to the recipient context.
     */
    SetupRecipient(privateKey: Key | KeyPair, encapsulatedKey: Uint8Array, options?: {
        info?: Uint8Array;
        psk?: Uint8Array;
        pskId?: Uint8Array;
    }): Promise<RecipientContext>;
}
/**
 * Error thrown when input validation fails.
 *
 * @ignore
 * @group Errors
 */
export declare class ValidationError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when key deserialization fails.
 *
 * @ignore
 * @group Errors
 */
export declare class DeserializeError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when encapsulation operation fails.
 *
 * @ignore
 * @group Errors
 */
export declare class EncapError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when decapsulation operation fails.
 *
 * @ignore
 * @group Errors
 */
export declare class DecapError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when AEAD decryption (open) operation fails.
 *
 * @ignore
 * @group Errors
 */
export declare class OpenError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when the message sequence number limit is reached.
 *
 * @ignore
 * @group Errors
 */
export declare class MessageLimitReachedError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when key pair derivation fails.
 *
 * @ignore
 * @group Errors
 */
export declare class DeriveKeyPairError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Error thrown when the runtime doesn't support an algorithm.
 *
 * @ignore
 * @group Errors
 */
export declare class NotSupportedError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
interface Triple {
    readonly id: Uint8Array;
    readonly KEM: Readonly<KEM>;
    readonly KDF: Readonly<KDF>;
    readonly AEAD: Readonly<AEAD>;
}
/** Mode identifier for Base mode */
export declare const MODE_BASE = 0;
/** Mode identifier for PSK mode */
export declare const MODE_PSK = 1;
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
export type KEMFactory = () => Readonly<KEM>;
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
export type KDFFactory = () => Readonly<KDF>;
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
export type AEADFactory = () => Readonly<AEAD>;
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
    readonly publicKey: Readonly<Key>;
    /** The private key, used for decryption operations. */
    readonly privateKey: Readonly<Key>;
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
        name: string;
    };
    /** Whether the key material can be extracted. */
    readonly extractable: boolean;
    /** The type of key: 'private' or 'public' */
    readonly type: 'private' | 'public' | (string & {});
}
/**
 * Concatenates multiple Uint8Array buffers into a single Uint8Array. It's exported for use in
 * custom KEM, KDF, or AEAD implementations.
 *
 * @param buffers - Variable number of Uint8Array buffers to concatenate
 *
 * @returns A new Uint8Array containing all input buffers concatenated in order
 * @group Utilities
 */
export declare function concat(...buffers: Uint8Array[]): Uint8Array;
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
export declare function encode(string: string): Uint8Array;
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
export declare function LabeledDerive(KDF: Pick<KDF, 'Derive'>, suite_id: Uint8Array, ikm: Uint8Array, label: Uint8Array, context: Uint8Array, L: number): Promise<Uint8Array>;
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














































 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface KDF {
    /** KDF algorithm identifier */
    readonly id: number;
    /** Type discriminator, always 'KDF' */
    readonly type: 'KDF';
    /** Human-readable name of the KDF algorithm */
    readonly name: string;
    /**
     * For one-stage KDFs, the security strength of the KDF in bytes.
     *
     * For two-stage KDFs, the output size of the {@link Extract} function in bytes.
     */
    readonly Nh: number;
    /** Number of stages (1 or 2) indicating one-stage or two-stage KDF */
    readonly stages: 1 | 2;
    /**
     * Extracts a pseudorandom key from input keying material.
     *
     * @param salt - Salt value
     * @param ikm - Input keying material
     *
     * @returns A promise resolving to the pseudorandom key
     */
    Extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>;
    /**
     * Expands a pseudorandom key to the desired length.
     *
     * @param prk - Pseudorandom key
     * @param info - Context and application-specific information
     * @param L - Desired length of output keying material in bytes
     *
     * @returns A promise resolving to the output keying material
     */
    Expand(prk: Uint8Array, info: Uint8Array, L: number): Promise<Uint8Array>;
    /**
     * Derives output keying material directly from labeled input keying material.
     *
     * @param labeled_ikm - Labeled input keying material
     * @param L - Desired length of output keying material in bytes
     *
     * @returns A promise resolving to the output keying material
     */
    Derive(labeled_ikm: Uint8Array, L: number): Promise<Uint8Array>;
}
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
export declare function LabeledExtract(KDF: Pick<KDF, 'Extract'>, suite_id: Uint8Array, salt: Uint8Array, label: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>;
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
export declare function LabeledExpand(KDF: Pick<KDF, 'Expand'>, suite_id: Uint8Array, prk: Uint8Array, label: Uint8Array, info: Uint8Array, L: number): Promise<Uint8Array>;
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















































































 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface KEM {
    /** KEM algorithm identifier */
    readonly id: number;
    /** Type discriminator, always 'KEM' */
    readonly type: 'KEM';
    /** Human-readable name of the KEM algorithm */
    readonly name: string;
    /** Length in bytes of a KEM shared secret produced by this KEM */
    readonly Nsecret: number;
    /** Length in bytes of an encapsulated secret produced by this KEM */
    readonly Nenc: number;
    /** Length in bytes of a public key for this KEM */
    readonly Npk: number;
    /** Length in bytes of a private key for this KEM */
    readonly Nsk: number;
    /**
     * Derives a key pair deterministically from input keying material.
     *
     * @param ikm - Input keying material already validated to be at least {@link Nsk} bytes
     * @param extractable - Whether the private key should be extractable
     *
     * @returns A promise resolving to a {@link KeyPair}
     */
    DeriveKeyPair(ikm: Uint8Array, extractable: boolean): Promise<KeyPair>;
    /**
     * Generates a random key pair.
     *
     * @param extractable - Whether the private key should be extractable
     *
     * @returns A promise resolving to a {@link KeyPair}
     */
    GenerateKeyPair(extractable: boolean): Promise<KeyPair>;
    /**
     * Serializes a public key to bytes.
     *
     * @param key - The public Key to serialize
     *
     * @returns A promise resolving to the serialized public key
     */
    SerializePublicKey(key: Key): Promise<Uint8Array>;
    /**
     * Deserializes a public key from bytes.
     *
     * @param key - The serialized public key already validated to be at least {@link Npk} bytes
     *
     * @returns A promise resolving to a {@link !Key} or a Key interface-conforming object
     */
    DeserializePublicKey(key: Uint8Array): Promise<Key>;
    /**
     * Serializes a private key to bytes.
     *
     * @param key - The private Key to serialize
     *
     * @returns A promise resolving to the serialized private key
     */
    SerializePrivateKey(key: Key): Promise<Uint8Array>;
    /**
     * Deserializes a private key from bytes.
     *
     * @param key - The serialized private key already validated to be at least {@link Nsk} bytes
     * @param extractable - Whether the private key should be extractable
     *
     * @returns A promise resolving to a {@link !Key} or a Key interface-conforming object
     */
    DeserializePrivateKey(key: Uint8Array, extractable: boolean): Promise<Key>;
    /**
     * Encapsulates a shared secret to a recipient's public key.
     *
     * This is the sender-side operation that generates an ephemeral key pair, performs the KEM
     * operation, and returns both the shared secret and the encapsulated key to send to the
     * recipient.
     *
     * @param pkR - The recipient's public key
     *
     * @returns A promise resolving to an object containing the shared secret and encapsulated key
     */
    Encap(pkR: Key): Promise<{
        shared_secret: Uint8Array;
        enc: Uint8Array;
    }>;
    /**
     * Decapsulates a shared secret using a recipient's private key.
     *
     * This is the recipient-side operation that uses the private key to extract the shared secret
     * from the encapsulated key.
     *
     * @param enc - The encapsulated key of {@link Nenc} length
     * @param skR - The recipient's private key
     * @param pkR - The recipient's public key (when user input to {@link CipherSuite.SetupRecipient}
     *   is a {@link KeyPair})
     *
     * @returns A promise resolving to the shared secret
     */
    Decap(enc: Uint8Array, skR: Key, pkR: Key | undefined): Promise<Uint8Array>;
}
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









































 * @see [HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)
 */
export interface AEAD {
    /** AEAD algorithm identifier */
    readonly id: number;
    /** Type discriminator, always 'AEAD' */
    readonly type: 'AEAD';
    /** Human-readable name of the AEAD algorithm */
    readonly name: string;
    /** Length in bytes of a key for this AEAD */
    readonly Nk: number;
    /** Length in bytes of a nonce for this AEAD */
    readonly Nn: number;
    /** Length in bytes of the authentication tag for this AEAD */
    readonly Nt: number;
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
    Seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array>;
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
    Open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array>;
}
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
export declare function I2OSP(n: number, w: number): Uint8Array;
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
export declare const AEAD_EXPORT_ONLY: AEADFactory;
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
export declare const KDF_HKDF_SHA256: KDFFactory;
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
export declare const KDF_HKDF_SHA384: KDFFactory;
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
export declare const KDF_HKDF_SHA512: KDFFactory;
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
export declare const KDF_SHAKE128: KDFFactory;
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
export declare const KDF_SHAKE256: KDFFactory;
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
export declare const KEM_DHKEM_P256_HKDF_SHA256: KEMFactory;
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
export declare const KEM_DHKEM_P384_HKDF_SHA384: KEMFactory;
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
export declare const KEM_DHKEM_P521_HKDF_SHA512: KEMFactory;
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
export declare const KEM_DHKEM_X25519_HKDF_SHA256: KEMFactory;
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
export declare const KEM_DHKEM_X448_HKDF_SHA512: KEMFactory;
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
export declare const KEM_ML_KEM_512: KEMFactory;
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
export declare const KEM_ML_KEM_768: KEMFactory;
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
export declare const KEM_ML_KEM_1024: KEMFactory;
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
export declare const AEAD_AES_128_GCM: AEADFactory;
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
export declare const AEAD_AES_256_GCM: AEADFactory;
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
export declare const AEAD_ChaCha20Poly1305: AEADFactory;
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
export declare const KEM_MLKEM768_X25519: KEMFactory;
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
export declare const KEM_MLKEM768_P256: KEMFactory;
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
export declare const KEM_MLKEM1024_P384: KEMFactory;
