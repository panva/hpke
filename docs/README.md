# @panva/hpke

Hybrid Public Key Encryption (HPKE) implementation for JavaScript runtimes.

Implements an authenticated encryption encapsulation format that combines a semi-static
asymmetric key exchange with a symmetric cipher. This was originally defined in an Informational
document on the IRTF stream as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and is now
being republished as a Standards Track document of the IETF as
[draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02).

HPKE provides a variant of public key encryption for arbitrary-sized plaintexts using a recipient
public key.

## Example

Getting started with [CipherSuite](classes/CipherSuite.md)

```ts
import * as HPKE from '@panva/hpke'

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

- [CipherSuite](classes/CipherSuite.md)
- [RecipientContext](interfaces/RecipientContext.md)
- [SenderContext](interfaces/SenderContext.md)

## KEM Algorithms

- [KEM\_DHKEM\_P256\_HKDF\_SHA256](variables/KEM_DHKEM_P256_HKDF_SHA256.md)
- [KEM\_DHKEM\_P384\_HKDF\_SHA384](variables/KEM_DHKEM_P384_HKDF_SHA384.md)
- [KEM\_DHKEM\_P521\_HKDF\_SHA512](variables/KEM_DHKEM_P521_HKDF_SHA512.md)
- [KEM\_DHKEM\_X25519\_HKDF\_SHA256](variables/KEM_DHKEM_X25519_HKDF_SHA256.md)
- [KEM\_DHKEM\_X448\_HKDF\_SHA512](variables/KEM_DHKEM_X448_HKDF_SHA512.md)
- [KEM\_ML\_KEM\_1024](variables/KEM_ML_KEM_1024.md)
- [KEM\_ML\_KEM\_512](variables/KEM_ML_KEM_512.md)
- [KEM\_ML\_KEM\_768](variables/KEM_ML_KEM_768.md)
- [KEM\_MLKEM1024\_P384](variables/KEM_MLKEM1024_P384.md)
- [KEM\_MLKEM768\_P256](variables/KEM_MLKEM768_P256.md)
- [KEM\_MLKEM768\_X25519](variables/KEM_MLKEM768_X25519.md)

## KDF Algorithms

- [KDF\_HKDF\_SHA256](variables/KDF_HKDF_SHA256.md)
- [KDF\_HKDF\_SHA384](variables/KDF_HKDF_SHA384.md)
- [KDF\_HKDF\_SHA512](variables/KDF_HKDF_SHA512.md)
- [KDF\_SHAKE128](variables/KDF_SHAKE128.md)
- [KDF\_SHAKE256](variables/KDF_SHAKE256.md)

## AEAD Algorithms

- [AEAD\_AES\_128\_GCM](variables/AEAD_AES_128_GCM.md)
- [AEAD\_AES\_256\_GCM](variables/AEAD_AES_256_GCM.md)
- [AEAD\_ChaCha20Poly1305](variables/AEAD_ChaCha20Poly1305.md)
- [AEAD\_EXPORT\_ONLY](variables/AEAD_EXPORT_ONLY.md)

## Interfaces

- [AEAD](interfaces/AEAD.md)
- [KDF](interfaces/KDF.md)
- [KEM](interfaces/KEM.md)
- [Key](interfaces/Key.md)
- [KeyPair](interfaces/KeyPair.md)

## Type Aliases

- [AEADFactory](type-aliases/AEADFactory.md)
- [KDFFactory](type-aliases/KDFFactory.md)
- [KEMFactory](type-aliases/KEMFactory.md)

## Utilities

- [concat](functions/concat.md)
- [encode](functions/encode.md)
- [I2OSP](functions/I2OSP.md)
- [LabeledDerive](functions/LabeledDerive.md)
- [LabeledExpand](functions/LabeledExpand.md)
- [LabeledExtract](functions/LabeledExtract.md)

## Variables

- [MODE\_BASE](variables/MODE_BASE.md)
- [MODE\_PSK](variables/MODE_PSK.md)
