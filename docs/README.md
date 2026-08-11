# hpke

Hybrid Public Key Encryption (HPKE) implementation for JavaScript runtimes.

Implements an authenticated encryption encapsulation format that combines a semi-static
asymmetric key exchange with a symmetric cipher. This was originally defined in an Informational
document on the IRTF stream as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and is now
being republished as a Standards Track document of the IETF as
[draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04).

HPKE provides a variant of public key encryption for arbitrary-sized plaintexts using a recipient
public key.

## Example

Getting started with [CipherSuite](classes/CipherSuite.md)

```ts
import * as HPKE from 'hpke'

// 1. Choose a cipher suite
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// 2. Generate recipient key pair
const recipient = await suite.GenerateKeyPair()

// 3. Encrypt a message
const plaintext = new TextEncoder().encode('Hello, World!')
const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext)

// 4. Decrypt the message
const decrypted = await suite.Open(recipient.privateKey, encapsulatedSecret, ciphertext)
console.log(new TextDecoder().decode(decrypted)) // "Hello, World!"
```

## Core

| Name | Description |
| :------ | :------ |
| [CipherSuite](classes/CipherSuite.md) | Hybrid Public Key Encryption (HPKE) suite combining a KEM, KDF, and AEAD. |
| [RecipientContext](interfaces/RecipientContext.md) | Context for decrypting multiple messages and exporting secrets on the recipient side. |
| [SenderContext](interfaces/SenderContext.md) | Context for encrypting multiple messages and exporting secrets on the sender side. |

## KEM Algorithms

| Variable | Description |
| :------ | :------ |
| [KEM\_DHKEM\_P256\_HKDF\_SHA256](variables/KEM_DHKEM_P256_HKDF_SHA256.md) | Diffie-Hellman Key Encapsulation Mechanism using NIST P-256 curve and HKDF-SHA256. |
| [KEM\_DHKEM\_P384\_HKDF\_SHA384](variables/KEM_DHKEM_P384_HKDF_SHA384.md) | Diffie-Hellman Key Encapsulation Mechanism using NIST P-384 curve and HKDF-SHA384. |
| [KEM\_DHKEM\_P521\_HKDF\_SHA512](variables/KEM_DHKEM_P521_HKDF_SHA512.md) | Diffie-Hellman Key Encapsulation Mechanism using NIST P-521 curve and HKDF-SHA512. |
| [KEM\_DHKEM\_X25519\_HKDF\_SHA256](variables/KEM_DHKEM_X25519_HKDF_SHA256.md) | Diffie-Hellman Key Encapsulation Mechanism using Curve25519 and HKDF-SHA256. |
| [KEM\_DHKEM\_X448\_HKDF\_SHA512](variables/KEM_DHKEM_X448_HKDF_SHA512.md) | Diffie-Hellman Key Encapsulation Mechanism using Curve448 and HKDF-SHA512. |
| [KEM\_ML\_KEM\_1024](variables/KEM_ML_KEM_1024.md) | Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-1024). |
| [KEM\_ML\_KEM\_512](variables/KEM_ML_KEM_512.md) | Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-512). |
| [KEM\_ML\_KEM\_768](variables/KEM_ML_KEM_768.md) | Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-768). |
| [KEM\_MLKEM1024\_P384](variables/KEM_MLKEM1024_P384.md) | Hybrid KEM combining ML-KEM-1024 with P-384 (MLKEM1024-P384). |
| [KEM\_MLKEM768\_P256](variables/KEM_MLKEM768_P256.md) | Hybrid KEM combining ML-KEM-768 with P-256 (MLKEM768-P256). |
| [KEM\_MLKEM768\_X25519](variables/KEM_MLKEM768_X25519.md) | Hybrid KEM combining ML-KEM-768 with X25519 (MLKEM768-X25519). |

## KDF Algorithms

| Variable | Description |
| :------ | :------ |
| [KDF\_HKDF\_SHA256](variables/KDF_HKDF_SHA256.md) | HKDF-SHA256 key derivation function. |
| [KDF\_HKDF\_SHA384](variables/KDF_HKDF_SHA384.md) | HKDF-SHA384 key derivation function. |
| [KDF\_HKDF\_SHA512](variables/KDF_HKDF_SHA512.md) | HKDF-SHA512 key derivation function. |
| [KDF\_SHAKE128](variables/KDF_SHAKE128.md) | SHAKE128 key derivation function. |
| [KDF\_SHAKE256](variables/KDF_SHAKE256.md) | SHAKE256 key derivation function. |
| [KDF\_TurboSHAKE128](variables/KDF_TurboSHAKE128.md) | TurboSHAKE128 key derivation function. |
| [KDF\_TurboSHAKE256](variables/KDF_TurboSHAKE256.md) | TurboSHAKE256 key derivation function. |

## AEAD Algorithms

| Variable | Description |
| :------ | :------ |
| [AEAD\_AES\_128\_GCM](variables/AEAD_AES_128_GCM.md) | AES-128-GCM Authenticated Encryption with Associated Data (AEAD). |
| [AEAD\_AES\_256\_GCM](variables/AEAD_AES_256_GCM.md) | AES-256-GCM Authenticated Encryption with Associated Data (AEAD). |
| [AEAD\_ChaCha20Poly1305](variables/AEAD_ChaCha20Poly1305.md) | ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD). |
| [AEAD\_EXPORT\_ONLY](variables/AEAD_EXPORT_ONLY.md) | Export-only AEAD mode. |

## Interfaces

| Interface | Description |
| :------ | :------ |
| [AEAD](interfaces/AEAD.md) | Authenticated Encryption with Associated Data (AEAD) implementation interface. |
| [KDF](interfaces/KDF.md) | Key Derivation Function (KDF) implementation interface. |
| [KEM](interfaces/KEM.md) | Key Encapsulation Mechanism (KEM) implementation interface. |
| [Key](interfaces/Key.md) | A minimal key representation interface. |
| [KeyPair](interfaces/KeyPair.md) | Represents a cryptographic key pair consisting of a public key and private key. |

## Type Aliases

| Type Alias | Description |
| :------ | :------ |
| [AEADFactory](type-aliases/AEADFactory.md) | Factory function that returns an AEAD implementation. |
| [CryptoKey](type-aliases/CryptoKey.md) | A Web Cryptography key as declared by the host runtime. |
| [KDFFactory](type-aliases/KDFFactory.md) | Factory function that returns a KDF implementation. |
| [KEMFactory](type-aliases/KEMFactory.md) | Factory function that returns a KEM implementation. |
| [Mode](type-aliases/Mode.md) | Mode supported by this implementation. |

## Utilities

| Function | Description |
| :------ | :------ |
| [concat](functions/concat.md) | Concatenates multiple Uint8Array buffers into a single Uint8Array. It's exported for use in custom KEM, KDF, or AEAD implementations. |
| [encode](functions/encode.md) | Encodes an ASCII string into a Uint8Array. |
| [I2OSP](functions/I2OSP.md) | Integer to Octet String Primitive (I2OSP) as defined in RFC 8017. Converts a non-negative integer into a byte string of specified length. It's exported for use in custom KEM, KDF, or AEAD implementations. |
| [LabeledDerive](functions/LabeledDerive.md) | Performs labeled key derivation for one-stage KDFs. |
| [LabeledExpand](functions/LabeledExpand.md) | Performs labeled expansion for two-stage KDFs. |
| [LabeledExtract](functions/LabeledExtract.md) | Performs labeled extraction for two-stage KDFs. |

## Variables

| Variable | Description |
| :------ | :------ |
| [MODE\_BASE](variables/MODE_BASE.md) | Mode identifier for Base mode (0x00). |
| [MODE\_PSK](variables/MODE_PSK.md) | Mode identifier for PSK mode (0x01). |
