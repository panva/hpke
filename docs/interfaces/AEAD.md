# Interface: AEAD

Authenticated Encryption with Associated Data (AEAD) implementation interface.

This implementation interface defines the contract for additional AEAD implementations to be
usable with [CipherSuite](../classes/CipherSuite.md). While this module provides built-in AEAD implementations based on
[Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
custom AEAD implementations that may not rely on Web Cryptography (e.g., using native bindings,
alternative crypto libraries, or specialized hardware).

Custom AEAD implementations must conform to this interface to be compatible with
[CipherSuite](../classes/CipherSuite.md) and its APIs.

## Contents

- [Methods](#methods)
  - [Open()](#open)
  - [Seal()](#seal)
- [Properties](#properties)
  - [id](#id)
  - [name](#name)
  - [Nk](#nk)
  - [Nn](#nn)
  - [Nt](#nt)
  - [type](#type)

## Example

```ts
import * as HPKE from 'hpke'

// Using a built-in AEAD
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Creating and using a custom AEAD implementation
const customAEAD: HPKE.AEADFactory = (): HPKE.AEAD => ({
  id: 0x9999,
  type: 'AEAD',
  name: 'Custom-AEAD',
  Nk: 16,
  Nn: 12,
  Nt: 16,
  async Seal(key, nonce, aad, pt) {
    // perform AEAD
    let ciphertext!: Uint8Array

    return ciphertext
  },
  async Open(key, nonce, aad, ct) {
    // perform AEAD
    let plaintext!: Uint8Array

    return plaintext
  },
})

const customSuite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  customAEAD,
)
```

## See

[HPKE AEAD Encryption Algorithm](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-4.3)

## Methods

### Open()

> **Open**(`key`, `nonce`, `aad`, `ct`): `Promise`<`Uint8Array`>

Decrypts and verifies ciphertext with associated data.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `Uint8Array` | The decryption key of [Nk](#nk) bytes |
| `nonce` | `Uint8Array` | The nonce of [Nn](#nn) bytes |
| `aad` | `Uint8Array` | Additional authenticated data |
| `ct` | `Uint8Array` | Ciphertext with authentication tag appended |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the decrypted plaintext

***

### Seal()

> **Seal**(`key`, `nonce`, `aad`, `pt`): `Promise`<`Uint8Array`>

Encrypts and authenticates plaintext with associated data.

Implementations must enforce the AEAD algorithm's per-invocation plaintext length limit (P\_MAX)
before encryption. HPKE's explicit error list maps `MessageLimitReachedError` to context
sequence number overflow; it does not prescribe a specific error for P\_MAX violations. Report
them as ordinary input range errors, such as `RangeError`.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `Uint8Array` | The encryption key of [Nk](#nk) bytes |
| `nonce` | `Uint8Array` | The nonce of [Nn](#nn) bytes |
| `aad` | `Uint8Array` | Additional authenticated data |
| `pt` | `Uint8Array` | Plaintext to encrypt |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the ciphertext with authentication tag appended

#### See

[Context.Seal P\_MAX handling](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-5.2)

## Properties

### id

> `readonly` **id**: `number`

AEAD algorithm identifier

***

### name

> `readonly` **name**: `string`

Human-readable name of the AEAD algorithm

***

### Nk

> `readonly` **Nk**: `number`

Length in bytes of a key for this AEAD

***

### Nn

> `readonly` **Nn**: `number`

Length in bytes of a nonce for this AEAD

***

### Nt

> `readonly` **Nt**: `number`

Length in bytes of the authentication tag for this AEAD

***

### type

> `readonly` **type**: `"AEAD"`

Type discriminator, always 'AEAD'
