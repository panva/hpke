# Interface: RecipientContext

Context for decrypting multiple messages and exporting secrets on the recipient side.

`RecipientContext` instance is obtained from [CipherSuite.SetupRecipient](../classes/CipherSuite.md#setuprecipient).

## Contents

- [Methods](#methods)
  - [Export()](#export)
  - [Open()](#open)
- [Accessors](#accessors)
  - [mode](#mode)
  - [seq](#seq)

## Example

```ts
let suite!: HPKE.CipherSuite
let privateKey!: HPKE.Key | HPKE.KeyPair

// ... receive encapsulatedKey from sender
let encapsulatedKey!: Uint8Array

const ctx: HPKE.RecipientContext = await suite.SetupRecipient(privateKey, encapsulatedKey)
```

## Methods

### Export()

> **Export**(`exporterContext`, `length`): `Promise`<`Uint8Array`>

Exports a secret using a variable-length pseudorandom function (PRF).

The exported secret is indistinguishable from a uniformly random bitstring of equal length.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `exporterContext` | `Uint8Array` | Context for domain separation |
| `length` | `number` | Desired length of exported secret in bytes |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the exported secret.

#### Example

```ts
let ctx!: HPKE.RecipientContext

// Export a 32-byte secret
const exporterContext: Uint8Array = new TextEncoder().encode('exporter context')
const exported: Uint8Array = await ctx.Export(exporterContext, 32)

// The sender can derive the same secret using the same exporterContext
```

***

### Open()

> **Open**(`ciphertext`, `aad?`): `Promise`<`Uint8Array`>

Decrypts ciphertext with additional authenticated data.

Applications must ensure that ciphertexts are presented to `Open` in the exact order they were
produced by the sender.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `ciphertext` | `Uint8Array` | Ciphertext to decrypt |
| `aad?` | `Uint8Array` | Additional authenticated data (must match sender's `aad`) |

#### Returns

`Promise`<`Uint8Array`>

A Promise that resolves to the decrypted plaintext.

#### Example

```ts
let ctx!: HPKE.RecipientContext

// Decrypt multiple messages with the same context
let aad1!: Uint8Array | undefined
let ct1!: Uint8Array
const pt1: Uint8Array = await ctx.Open(ct1, aad1)

let aad2!: Uint8Array | undefined
let ct2!: Uint8Array
const pt2: Uint8Array = await ctx.Open(ct2, aad2)
```

## Accessors

### mode

#### Get Signature

> **get** **mode**(): `number`

##### Returns

`number`

The mode (0x00 = Base, 0x01 = PSK) for this context.

***

### seq

#### Get Signature

> **get** **seq**(): `number`

##### Returns

`number`

The sequence number for this context's next [Open](#open), initially zero, increments
automatically with each successful [Open](#open). The sequence number provides AEAD nonce
uniqueness.
