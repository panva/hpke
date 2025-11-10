# Interface: KEM

Key Encapsulation Mechanism (KEM) implementation interface.

This implementation interface defines the contract for additional KEM implementations to be
usable with [CipherSuite](../classes/CipherSuite.md). While this module provides built-in KEM implementations based on
[Web Cryptography](https://www.w3.org/TR/webcrypto-2/), this interface is exported to allow
custom KEM implementations that may not rely on Web Cryptography (e.g., using native bindings,
alternative crypto libraries, or specialized hardware).

Custom KEM implementations must conform to this interface to be compatible with
[CipherSuite](../classes/CipherSuite.md) and its APIs.

## Contents

- [Methods](#methods)
  - [Decap()](#decap)
  - [DeriveKeyPair()](#derivekeypair)
  - [DeserializePrivateKey()](#deserializeprivatekey)
  - [DeserializePublicKey()](#deserializepublickey)
  - [Encap()](#encap)
  - [GenerateKeyPair()](#generatekeypair)
  - [SerializePrivateKey()](#serializeprivatekey)
  - [SerializePublicKey()](#serializepublickey)
- [Properties](#properties)
  - [id](#id)
  - [name](#name)
  - [Nenc](#nenc)
  - [Npk](#npk)
  - [Nsecret](#nsecret)
  - [Nsk](#nsk)
  - [type](#type)

## Example

```ts
import * as HPKE from '@panva/hpke'

// Using a built-in KEM
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// Creating and using a custom KEM implementation
const customKEM: HPKE.KEMFactory = (): HPKE.KEM => ({
  id: 0x9999,
  type: 'KEM',
  name: 'Custom-KEM',
  Nsecret: 32,
  Nenc: 32,
  Npk: 32,
  Nsk: 32,
  async DeriveKeyPair(ikm, extractable) {
    // perform DeriveKeyPair
    let kp!: HPKE.KeyPair

    return kp
  },
  async GenerateKeyPair(extractable) {
    // perform GenerateKeyPair
    let kp!: HPKE.KeyPair

    return kp
  },
  async SerializePublicKey(key) {
    // perform SerializePublicKey
    let public_key!: Uint8Array

    return public_key
  },
  async DeserializePublicKey(key) {
    // perform DeserializePublicKey
    let public_key!: HPKE.Key

    return public_key
  },
  async SerializePrivateKey(key) {
    // perform SerializePrivateKey
    let private_key!: Uint8Array

    return private_key
  },
  async DeserializePrivateKey(key, extractable) {
    // perform DeserializePrivateKey
    let private_key!: HPKE.Key

    return private_key
  },
  async Encap(pkR) {
    // perform Encap
    let shared_secret!: Uint8Array
    let enc!: Uint8Array

    return { shared_secret, enc }
  },
  async Decap(enc, skR, pkR) {
    // perform Decap
    let shared_secret!: Uint8Array

    return shared_secret
  },
})

const customSuite = new HPKE.CipherSuite(
  customKEM,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)
```

## See

[HPKE Cryptographic Dependencies](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4)

## Methods

### Decap()

> **Decap**(`enc`, `skR`, `pkR`): `Promise`<`Uint8Array`>

Decapsulates a shared secret using a recipient's private key.

This is the recipient-side operation that uses the private key to extract the shared secret
from the encapsulated key.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `enc` | `Uint8Array` | The encapsulated key of [Nenc](#nenc) length |
| `skR` | [`Key`](Key.md) | The recipient's private key |
| `pkR` | [`Key`](Key.md) ∣ `undefined` | The recipient's public key (when user input to [CipherSuite.SetupRecipient](../classes/CipherSuite.md#setuprecipient) is a [KeyPair](KeyPair.md)) |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the shared secret

***

### DeriveKeyPair()

> **DeriveKeyPair**(`ikm`, `extractable`): `Promise`<[`KeyPair`](KeyPair.md)>

Derives a key pair deterministically from input keying material.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `ikm` | `Uint8Array` | Input keying material already validated to be at least [Nsk](#nsk) bytes |
| `extractable` | `boolean` | Whether the private key should be extractable |

#### Returns

`Promise`<[`KeyPair`](KeyPair.md)>

A promise resolving to a [KeyPair](KeyPair.md)

***

### DeserializePrivateKey()

> **DeserializePrivateKey**(`key`, `extractable`): `Promise`<[`Key`](Key.md)>

Deserializes a private key from bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `Uint8Array` | The serialized private key already validated to be at least [Nsk](#nsk) bytes |
| `extractable` | `boolean` | Whether the private key should be extractable |

#### Returns

`Promise`<[`Key`](Key.md)>

A promise resolving to a [!Key](Key.md) or a Key interface-conforming object

***

### DeserializePublicKey()

> **DeserializePublicKey**(`key`): `Promise`<[`Key`](Key.md)>

Deserializes a public key from bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `Uint8Array` | The serialized public key already validated to be at least [Npk](#npk) bytes |

#### Returns

`Promise`<[`Key`](Key.md)>

A promise resolving to a [!Key](Key.md) or a Key interface-conforming object

***

### Encap()

> **Encap**(`pkR`): `Promise`<{ `enc`: `Uint8Array`; `shared_secret`: `Uint8Array`; }>

Encapsulates a shared secret to a recipient's public key.

This is the sender-side operation that generates an ephemeral key pair, performs the KEM
operation, and returns both the shared secret and the encapsulated key to send to the
recipient.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `pkR` | [`Key`](Key.md) | The recipient's public key |

#### Returns

`Promise`<{ `enc`: `Uint8Array`; `shared_secret`: `Uint8Array`; }>

A promise resolving to an object containing the shared secret and encapsulated key

***

### GenerateKeyPair()

> **GenerateKeyPair**(`extractable`): `Promise`<[`KeyPair`](KeyPair.md)>

Generates a random key pair.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable` | `boolean` | Whether the private key should be extractable |

#### Returns

`Promise`<[`KeyPair`](KeyPair.md)>

A promise resolving to a [KeyPair](KeyPair.md)

***

### SerializePrivateKey()

> **SerializePrivateKey**(`key`): `Promise`<`Uint8Array`>

Serializes a private key to bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | [`Key`](Key.md) | The private Key to serialize |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the serialized private key

***

### SerializePublicKey()

> **SerializePublicKey**(`key`): `Promise`<`Uint8Array`>

Serializes a public key to bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | [`Key`](Key.md) | The public Key to serialize |

#### Returns

`Promise`<`Uint8Array`>

A promise resolving to the serialized public key

## Properties

### id

> `readonly` **id**: `number`

KEM algorithm identifier

***

### name

> `readonly` **name**: `string`

Human-readable name of the KEM algorithm

***

### Nenc

> `readonly` **Nenc**: `number`

Length in bytes of an encapsulated secret produced by this KEM

***

### Npk

> `readonly` **Npk**: `number`

Length in bytes of a public key for this KEM

***

### Nsecret

> `readonly` **Nsecret**: `number`

Length in bytes of a KEM shared secret produced by this KEM

***

### Nsk

> `readonly` **Nsk**: `number`

Length in bytes of a private key for this KEM

***

### type

> `readonly` **type**: `"KEM"`

Type discriminator, always 'KEM'
