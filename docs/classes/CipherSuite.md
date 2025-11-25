# Class: CipherSuite

Hybrid Public Key Encryption (HPKE) suite combining a KEM, KDF, and AEAD.

Implements an authenticated encryption encapsulation format that combines a semi-static
asymmetric key exchange with a symmetric cipher. This was originally defined in an Informational
document on the IRTF stream as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and is now
being republished as a Standards Track document of the IETF as
[draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02).

HPKE provides a variant of public key encryption for arbitrary-sized plaintexts using a recipient
public key. It supports two modes:

- Base mode: Encryption to a public key without sender authentication
- PSK mode: Encryption with pre-shared key authentication

The cipher suite consists of:

- KEM: Key Encapsulation Mechanism for establishing shared secrets
- KDF: Key Derivation Function for deriving symmetric keys
- AEAD: Authenticated Encryption with Additional Data for encryption

## Contents

- [Constructor](#constructor)
- [Encryption Context](#encryption-context)
  - [SetupRecipient()](#setuprecipient)
  - [SetupSender()](#setupsender)
- [Key Management](#key-management)
  - [DeriveKeyPair()](#derivekeypair)
  - [DeserializePrivateKey()](#deserializeprivatekey)
  - [DeserializePublicKey()](#deserializepublickey)
  - [GenerateKeyPair()](#generatekeypair)
  - [SerializePrivateKey()](#serializeprivatekey)
  - [SerializePublicKey()](#serializepublickey)
- [Single-Shot APIs](#single-shot-apis)
  - [Open()](#open)
  - [ReceiveExport()](#receiveexport)
  - [Seal()](#seal)
  - [SendExport()](#sendexport)
- [Other](#other)
  - [AEAD](#aead)
  - [KDF](#kdf)
  - [KEM](#kem)

## Constructor

> **new CipherSuite**(`KEM`, `KDF`, `AEAD`): `CipherSuite`

Creates a new HPKE cipher suite by combining a Key Encapsulation Mechanism (KEM), Key
Derivation Function (KDF), and an Authenticated Encryption with Associated Data (AEAD)
algorithm.

A cipher suite defines the complete cryptographic configuration for HPKE operations. The choice
of algorithms affects security properties, performance, and compatibility across different
platforms and runtimes.

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `KEM` | [`KEMFactory`](../type-aliases/KEMFactory.md) | KEM implementation factory. Must return an object conforming to the [KEM](#constructorciphersuite) interface. |
| `KDF` | [`KDFFactory`](../type-aliases/KDFFactory.md) | KDF implementation factory. Must return an object conforming to the [KDF](#constructorciphersuite) interface. |
| `AEAD` | [`AEADFactory`](../type-aliases/AEADFactory.md) | AEAD implementation factory. Must return an object conforming to the [AEAD](#constructorciphersuite) interface. |

### Returns

`CipherSuite`

### Examples

Traditional algorithms

```ts
import * as HPKE from '@panva/hpke'

const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)
```

Hybrid post-quantum/traditional (PQ/T) KEM

```ts
import * as HPKE from '@panva/hpke'

const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
  HPKE.KEM_MLKEM768_X25519,
  HPKE.KDF_SHAKE256,
  HPKE.AEAD_ChaCha20Poly1305,
)
```

Post-quantum (PQ) KEM

```ts
import * as HPKE from '@panva/hpke'

const suite: HPKE.CipherSuite = new HPKE.CipherSuite(
  HPKE.KEM_ML_KEM_768,
  HPKE.KDF_SHAKE256,
  HPKE.AEAD_ChaCha20Poly1305,
)
```

### See

- [Available KEMs](../type-aliases/KEMFactory.md)
- [Available KDFs](../type-aliases/KDFFactory.md)
- [Available AEADs](../type-aliases/AEADFactory.md)

## Encryption Context

### SetupRecipient()

> **SetupRecipient**(`privateKey`, `encapsulatedKey`, `options?`): `Promise`<[`RecipientContext`](../interfaces/RecipientContext.md)>

Establishes a recipient decryption context.

Creates a context that can be used to decrypt multiple messages from the same sender.

Mode selection:

- If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
- If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | [`KeyPair`](../interfaces/KeyPair.md) ∣ [`Key`](../interfaces/Key.md) | Recipient's private key or key pair |
| `encapsulatedKey` | `Uint8Array` | Encapsulated key from the sender |
| `options?` |  | Options |
| `options.info?` | `Uint8Array` | Application-supplied information (must match sender's `info`) |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK mode, must match sender's `psk`) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK mode, must match sender's `pskId`) |

#### Returns

`Promise`<[`RecipientContext`](../interfaces/RecipientContext.md)>

A Promise that resolves to the recipient context.

#### Example

```ts
let suite!: HPKE.CipherSuite
let privateKey!: HPKE.Key | HPKE.KeyPair

// ... receive encapsulatedKey from sender
let encapsulatedKey!: Uint8Array

const ctx: HPKE.RecipientContext = await suite.SetupRecipient(privateKey, encapsulatedKey)

// ... receive messages from sender

let aad1!: Uint8Array | undefined
let ct1!: Uint8Array

const pt1: Uint8Array = await ctx.Open(ct1, aad1)

let aad2!: Uint8Array | undefined
let ct2!: Uint8Array

const pt2: Uint8Array = await ctx.Open(ct2, aad2)
```

***

### SetupSender()

> **SetupSender**(`publicKey`, `options?`): `Promise`<{ `ctx`: [`SenderContext`](../interfaces/SenderContext.md); `encapsulatedKey`: `Uint8Array`; }>

Establishes a sender encryption context.

Creates a context that can be used to encrypt multiple messages to the same recipient,
amortizing the cost of the public key operations.

Mode selection:

- If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
- If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)

The returned context maintains a sequence number that increments with each encryption, ensuring
nonce uniqueness.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `publicKey` | [`Key`](../interfaces/Key.md) | Recipient's public key |
| `options?` |  | Options |
| `options.info?` | `Uint8Array` | Application-supplied information |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK modes) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK modes) |

#### Returns

`Promise`<{ `ctx`: [`SenderContext`](../interfaces/SenderContext.md); `encapsulatedKey`: `Uint8Array`; }>

A Promise that resolves to an object containing the encapsulated key and the sender
context (`ctx`). The encapsulated key is [Nenc](#kem) bytes.

#### Example

```ts
let suite!: HPKE.CipherSuite
let publicKey!: HPKE.Key // recipient's public key

const { encapsulatedKey, ctx } = await suite.SetupSender(publicKey)

// Encrypt multiple messages with the same context
const aad1: Uint8Array = new TextEncoder().encode('message 1 aad')
const pt1: Uint8Array = new TextEncoder().encode('First message')
const ct1: Uint8Array = await ctx.Seal(pt1, aad1)

const aad2: Uint8Array = new TextEncoder().encode('message 2 aad')
const pt2: Uint8Array = new TextEncoder().encode('Second message')
const ct2: Uint8Array = await ctx.Seal(pt2, aad2)
```

## Key Management

### DeriveKeyPair()

> **DeriveKeyPair**(`ikm`, `extractable?`): `Promise`<[`KeyPair`](../interfaces/KeyPair.md)>

Deterministically derives a key pair for this CipherSuite from input keying material. By
default, private keys are derived as non-extractable (their value cannot be exported).

An `ikm` input MUST NOT be reused elsewhere, particularly not with `DeriveKeyPair()` of a
different KEM.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `ikm` | `Uint8Array` | Input keying material (must be at least [Nsk](#kem) bytes) |
| `extractable?` | `boolean` | Whether the derived key pair's private key should be extractable (e.g. by [SerializePrivateKey](#serializeprivatekey)) (default: false) |

#### Returns

`Promise`<[`KeyPair`](../interfaces/KeyPair.md)>

A Promise that resolves to the derived key pair.

#### Example

```ts
let suite!: HPKE.CipherSuite
let ikm!: Uint8Array // ... previously serialized ikm of at least suite.KEM.Nsk length
const keyPair: HPKE.KeyPair = await suite.DeriveKeyPair(ikm)
```

***

### DeserializePrivateKey()

> **DeserializePrivateKey**(`privateKey`, `extractable?`): `Promise`<[`Key`](../interfaces/Key.md)>

Deserializes a private key from bytes. By default, private keys are deserialized as
non-extractable (their value cannot be exported).

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | `Uint8Array` | Serialized private key |
| `extractable?` | `boolean` | Whether the deserialized private key should be extractable (e.g. by [SerializePrivateKey](#serializeprivatekey)) (default: false) |

#### Returns

`Promise`<[`Key`](../interfaces/Key.md)>

A Promise that resolves to the deserialized private key.

#### Example

```ts
let suite!: HPKE.CipherSuite
let serialized!: Uint8Array // ... previously serialized key of suite.KEM.Nsk length
const privateKey: HPKE.Key = await suite.DeserializePrivateKey(serialized)
```

***

### DeserializePublicKey()

> **DeserializePublicKey**(`publicKey`): `Promise`<[`Key`](../interfaces/Key.md)>

Deserializes a public key from bytes. Public keys are always deserialized as extractable (their
value can be exported, e.g. by [SerializePublicKey](#serializepublickey)).

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `publicKey` | `Uint8Array` | Serialized public key |

#### Returns

`Promise`<[`Key`](../interfaces/Key.md)>

A Promise that resolves to the deserialized public key.

#### Example

```ts
let suite!: HPKE.CipherSuite
let serialized!: Uint8Array // ... previously serialized key of suite.KEM.Npk length
const publicKey: HPKE.Key = await suite.DeserializePublicKey(serialized)
```

***

### GenerateKeyPair()

> **GenerateKeyPair**(`extractable?`): `Promise`<[`KeyPair`](../interfaces/KeyPair.md)>

Generates a random key pair for this CipherSuite. By default, private keys are generated as
non-extractable (their value cannot be exported).

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the generated key pair's private key should be extractable (e.g. by [SerializePrivateKey](#serializeprivatekey)) (default: false) |

#### Returns

`Promise`<[`KeyPair`](../interfaces/KeyPair.md)>

A Promise that resolves to a generated key pair.

#### Example

```ts
let suite!: HPKE.CipherSuite
const keyPair: HPKE.KeyPair = await suite.GenerateKeyPair()
```

***

### SerializePrivateKey()

> **SerializePrivateKey**(`privateKey`): `Promise`<`Uint8Array`>

Serializes an extractable private key to bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | [`Key`](../interfaces/Key.md) | Private key to serialize |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the serialized private key.

#### Example

```ts
let suite!: HPKE.CipherSuite
let privateKey!: HPKE.Key
const serialized: Uint8Array = await suite.SerializePrivateKey(privateKey)
```

***

### SerializePublicKey()

> **SerializePublicKey**(`publicKey`): `Promise`<`Uint8Array`>

Serializes a public key to bytes.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `publicKey` | [`Key`](../interfaces/Key.md) | Public key to serialize |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the serialized public key.

#### Example

```ts
let suite!: HPKE.CipherSuite
let publicKey!: HPKE.Key
const serialized: Uint8Array = await suite.SerializePublicKey(publicKey)
```

## Single-Shot APIs

### Open()

> **Open**(`privateKey`, `encapsulatedKey`, `ciphertext`, `options?`): `Promise`<`Uint8Array`>

Single-shot API for decrypting a single message.

It combines context setup and decryption in one call.

Mode selection:

- If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
- If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | [`KeyPair`](../interfaces/KeyPair.md) ∣ [`Key`](../interfaces/Key.md) | Recipient's private key or key pair |
| `encapsulatedKey` | `Uint8Array` | Encapsulated key from the sender |
| `ciphertext` | `Uint8Array` | Ciphertext to decrypt |
| `options?` |  | Options |
| `options.aad?` | `Uint8Array` | Additional authenticated data (must match sender's `aad`) |
| `options.info?` | `Uint8Array` | Application-supplied information (must match sender's `info`) |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK mode, must match sender's `psk`) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK mode, must match sender's `pskId`) |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the decrypted plaintext.

#### Example

```ts
let suite!: HPKE.CipherSuite
let privateKey!: HPKE.Key | HPKE.KeyPair

// ... receive encapsulatedKey, ciphertext from sender
let encapsulatedKey!: Uint8Array
let ciphertext!: Uint8Array

const plaintext: Uint8Array = await suite.Open(privateKey, encapsulatedKey, ciphertext)
```

***

### ReceiveExport()

> **ReceiveExport**(`privateKey`, `encapsulatedKey`, `exporterContext`, `length`, `options?`): `Promise`<`Uint8Array`>

Single-shot API for receiving an exported secret.

It combines context setup and secret export in one call.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | [`KeyPair`](../interfaces/KeyPair.md) ∣ [`Key`](../interfaces/Key.md) | Recipient's private key or key pair |
| `encapsulatedKey` | `Uint8Array` | Encapsulated key from the sender |
| `exporterContext` | `Uint8Array` | Context of the export operation (must match sender's `exporterContext`) |
| `length` | `number` | Desired length of exported secret in bytes (must match sender's `L`) |
| `options?` |  | Options |
| `options.info?` | `Uint8Array` | Application-supplied information (must match sender's `info`) |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK mode, must match sender's `psk`) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK mode, must match sender's `pskId`) |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the exported secret.

#### Example

```ts
let suite!: HPKE.CipherSuite
let privateKey!: HPKE.Key | HPKE.KeyPair

const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')

// ... receive encapsulatedKey from sender
let encapsulatedKey!: Uint8Array

const exported: Uint8Array = await suite.ReceiveExport(
  privateKey,
  encapsulatedKey,
  exporterContext,
  32,
)
```

***

### Seal()

> **Seal**(`publicKey`, `plaintext`, `options?`): `Promise`<{ `ciphertext`: `Uint8Array`; `encapsulatedKey`: `Uint8Array`; }>

Single-shot API for encrypting a single message. It combines context setup and encryption in
one call.

Mode selection:

- If the options `psk` and `pskId` are omitted: Base mode (unauthenticated)
- If the options `psk` and `pskId` are provided: PSK mode (authenticated with pre-shared key)

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `publicKey` | [`Key`](../interfaces/Key.md) | Recipient's public key |
| `plaintext` | `Uint8Array` | Plaintext to encrypt |
| `options?` |  | Options |
| `options.aad?` | `Uint8Array` | Additional authenticated data passed to the AEAD |
| `options.info?` | `Uint8Array` | Application-supplied information |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK modes) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK modes) |

#### Returns

`Promise`<{ `ciphertext`: `Uint8Array`; `encapsulatedKey`: `Uint8Array`; }>

A Promise that resolves to an object containing the encapsulated key and ciphertext.
The ciphertext is [Nt](#aead) bytes longer than the plaintext. The
encapsulated key is [Nenc](#kem) bytes.

#### Example

```ts
let suite!: HPKE.CipherSuite
let publicKey!: HPKE.Key // recipient's public key

const plaintext: Uint8Array = new TextEncoder().encode('Hello, World!')

const { encapsulatedKey, ciphertext } = await suite.Seal(publicKey, plaintext)
```

***

### SendExport()

> **SendExport**(`publicKey`, `exporterContext`, `length`, `options?`): `Promise`<{ `encapsulatedKey`: `Uint8Array`; `exportedSecret`: `Uint8Array`; }>

Single-shot API for deriving a secret known only to sender and recipient.

It combines context setup and secret export in one call.

The exported secret is indistinguishable from a uniformly random bitstring of equal length.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `publicKey` | [`Key`](../interfaces/Key.md) | Recipient's public key |
| `exporterContext` | `Uint8Array` | Context of the export operation |
| `length` | `number` | Desired length of exported secret in bytes |
| `options?` |  | Options |
| `options.info?` | `Uint8Array` | Application-supplied information |
| `options.psk?` | `Uint8Array` | Pre-shared key (for PSK modes) |
| `options.pskId?` | `Uint8Array` | Pre-shared key identifier (for PSK modes) |

#### Returns

`Promise`<{ `encapsulatedKey`: `Uint8Array`; `exportedSecret`: `Uint8Array`; }>

A Promise that resolves to an object containing the encapsulated key and the exported
secret.

#### Example

```ts
let suite!: HPKE.CipherSuite
let publicKey!: HPKE.Key // recipient's public key

const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')

const { encapsulatedKey, exportedSecret } = await suite.SendExport(
  publicKey,
  exporterContext,
  32,
)
```

## Other

### AEAD

#### Get Signature

> **get** **AEAD**(): `object`

Provides read-only access to this suite's AEAD identifier, name, and other attributes.

##### Returns

An object with this suite's Authenticated Encryption with Associated Data (AEAD)
cipher properties.

###### id

> **id**: `number`

The identifier of this suite's AEAD

###### name

> **name**: `string`

The name of this suite's AEAD

###### Nk

> **Nk**: `number`

The length in bytes of a key for this suite's AEAD

###### Nn

> **Nn**: `number`

The length in bytes of a nonce for this suite's AEAD

###### Nt

> **Nt**: `number`

The length in bytes of an authentication tag for this suite's AEAD

***

### KDF

#### Get Signature

> **get** **KDF**(): `object`

Provides read-only access to this suite's KDF identifier, name, and other attributes.

##### Returns

An object with this suite's Key Derivation Function (KDF) properties.

###### id

> **id**: `number`

The identifier of this suite's KDF

###### name

> **name**: `string`

The name of this suite's KDF

###### Nh

> **Nh**: `number`

For one-stage KDF: The security strength of this suite's KDF, in bytes.

For two-stage KDF: The output size of this suite's KDF Extract() function in bytes.

###### stages

> **stages**: `1` ∣ `2`

When 1, this suite's KDF is a one-stage (Derive) KDF.

When 2, this suite's KDF is a two-stage (Extract and Expand) KDF.

***

### KEM

#### Get Signature

> **get** **KEM**(): `object`

Provides read-only access to this suite's KEM identifier, name, and other attributes.

##### Returns

An object with this suite's Key Encapsulation Mechanism (KEM) properties.

###### id

> **id**: `number`

The identifier of this suite's KEM

###### name

> **name**: `string`

The name of this suite's KEM

###### Nenc

> **Nenc**: `number`

The length in bytes of this suite's KEM produced encapsulated key

###### Npk

> **Npk**: `number`

The length in bytes of this suite's KEM public key

###### Nsecret

> **Nsecret**: `number`

The length in bytes of this suite's KEM produced shared secret

###### Nsk

> **Nsk**: `number`

The length in bytes of this suite's KEM private key
