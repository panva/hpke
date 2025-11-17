# Interface: SenderContext

Context for encrypting multiple messages and exporting secrets on the sender side.

`SenderContext` instance is obtained from [CipherSuite.SetupSender](../classes/CipherSuite.md#setupsender).

This context maintains an internal sequence number that increments with each [Seal](#seal)
operation, ensuring nonce uniqueness for the underlying AEAD algorithm.

## Contents

- [Methods](#methods)
  - [Export()](#export)
  - [Seal()](#seal)
- [Accessors](#accessors)
  - [mode](#mode)
  - [Nt](#nt)
  - [seq](#seq)

## Example

```ts
let suite!: HPKE.CipherSuite
let publicKey!: HPKE.Key // recipient's public key

const { encapsulatedKey, ctx } = await suite.SetupSender(publicKey)
```

## Methods

### Export()

> **Export**(`exporterContext`, `L`): `Promise`<`Uint8Array`>

Exports a secret using a variable-length pseudorandom function (PRF).

The exported secret is indistinguishable from a uniformly random bitstring of equal length.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `exporterContext` | `Uint8Array` | Context for domain separation |
| `L` | `number` | Desired length of exported secret in bytes |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the exported secret.

#### Example

```ts
let ctx!: HPKE.SenderContext

// Export a 32-byte secret
const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
const exportedSecret: Uint8Array = await ctx.Export(exporterContext, 32)

// The recipient can derive the same secret using the same exporterContext
```

***

### Seal()

> **Seal**(`plaintext`, `aad?`): `Promise`<`Uint8Array`>

Encrypts plaintext with additional authenticated data. Each successful call automatically
increments the sequence number to ensure nonce uniqueness.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `plaintext` | `Uint8Array` | Plaintext to encrypt |
| `aad?` | `Uint8Array` | Additional authenticated data |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the ciphertext. The ciphertext is [Nt](#nt) bytes longer
than the plaintext.

#### Example

```ts
let ctx!: HPKE.SenderContext

// Encrypt multiple messages with the same context
const aad1: Uint8Array = new TextEncoder().encode('message 1 aad')
const pt1: Uint8Array = new TextEncoder().encode('First message')
const ct1: Uint8Array = await ctx.Seal(pt1, aad1)

const aad2: Uint8Array = new TextEncoder().encode('message 2 aad')
const pt2: Uint8Array = new TextEncoder().encode('Second message')
const ct2: Uint8Array = await ctx.Seal(pt2, aad2)
```

## Accessors

### mode

#### Get Signature

> **get** **mode**(): `number`

##### Returns

`number`

The mode (0x00 = Base, 0x01 = PSK) for this context.

***

### Nt

#### Get Signature

> **get** **Nt**(): `number`

##### Returns

`number`

The length in bytes of an authentication tag for the AEAD algorithm used by this
context.

***

### seq

#### Get Signature

> **get** **seq**(): `number`

##### Returns

`number`

The sequence number for this context's next [Seal](#seal), initially zero, increments
automatically with each successful [Seal](#seal). The sequence number provides AEAD nonce
uniqueness.
