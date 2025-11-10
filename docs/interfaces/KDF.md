# Interface: KDF

Key Derivation Function (KDF) implementation interface.

This implementation interface defines the contract for additional KDF implementations to be
usable with [CipherSuite](../classes/CipherSuite.md). While this module provides built-in KDF implementations based on
[Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
custom KDF implementations that may not rely on Web Cryptography (e.g., using native bindings,
alternative crypto libraries, or specialized hardware).

Custom KDF implementations must conform to this interface to be compatible with
[CipherSuite](../classes/CipherSuite.md) and its APIs.

KDF implementations are either one-stage or two-stage:

- One-stage KDFs only implement [Derive](#derive). The [Extract](#extract) and [Expand](#expand) methods will
  not be called and may be no-op implementations.
- Two-stage KDFs only implement [Extract](#extract) and [Expand](#expand). The [Derive](#derive) method will not
  be called and may be a no-op implementation.

## Contents

- [Methods](#methods)
  - [Derive()](#derive)
  - [Expand()](#expand)
  - [Extract()](#extract)
- [Properties](#properties)
  - [id](#id)
  - [name](#name)
  - [Nh](#nh)
  - [stages](#stages)
  - [type](#type)

## Example

```ts
import * as HPKE from '@panva/hpke'

// Using a built-in KDF
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Creating and using a custom KDF implementation
const customKDF: HPKE.KDFFactory = (): HPKE.KDF => ({
  id: 0x9999,
  type: 'KDF',
  name: 'Custom-KDF',
  Nh: 32,
  stages: 2,
  async Extract(salt, ikm) {
    // perform Extract
    let result!: Uint8Array

    return result
  },
  async Expand(prk, info, L) {
    // perform Expand
    let result!: Uint8Array

    return result
  },
  async Derive(labeled_ikm, L) {
    // perform Derive
    let result!: Uint8Array

    return result
  },
})

const customSuite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  customKDF,
  HPKE.AEAD_AES_128_GCM,
)
```

## See

[HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)

## Methods

### Derive()

> **Derive**(`labeled_ikm`, `L`): `Promise`<`Uint8Array`>

Derives output keying material directly from labeled input keying material.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `labeled_ikm` | `Uint8Array` | Labeled input keying material |
| `L` | `number` | Desired length of output keying material in bytes |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the output keying material

***

### Expand()

> **Expand**(`prk`, `info`, `L`): `Promise`<`Uint8Array`>

Expands a pseudorandom key to the desired length.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `prk` | `Uint8Array` | Pseudorandom key |
| `info` | `Uint8Array` | Context and application-specific information |
| `L` | `number` | Desired length of output keying material in bytes |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the output keying material

***

### Extract()

> **Extract**(`salt`, `ikm`): `Promise`<`Uint8Array`>

Extracts a pseudorandom key from input keying material.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `salt` | `Uint8Array` | Salt value |
| `ikm` | `Uint8Array` | Input keying material |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the pseudorandom key

## Properties

### id

> `readonly` **id**: `number`

KDF algorithm identifier

***

### name

> `readonly` **name**: `string`

Human-readable name of the KDF algorithm

***

### Nh

> `readonly` **Nh**: `number`

For one-stage KDFs, the security strength of the KDF in bytes.

For two-stage KDFs, the output size of the [Extract](#extract) function in bytes.

***

### stages

> `readonly` **stages**: `1` ∣ `2`

Number of stages (1 or 2) indicating one-stage or two-stage KDF

***

### type

> `readonly` **type**: `"KDF"`

Type discriminator, always 'KDF'
