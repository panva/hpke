# Function: LabeledDerive()

> **LabeledDerive**(`KDF`, `suite_id`, `ikm`, `label`, `context`, `L`): `Promise`<`Uint8Array`>

Performs labeled key derivation for one-stage KDFs.

This function implements the LabeledDerive operation as specified in the HPKE specification for
use with one-stage KDFs. It constructs a labeled input by concatenating:

- The input keying material (`ikm`)
- The version string "HPKE-v1"
- The suite identifier (`suite_id`)
- A length-prefixed label
- The desired output length as a 2-byte encoding
- Additional context

The labeled input is then passed to the KDF's Derive function to produce L bytes of output. This
ensures domain separation between different uses of the KDF in HPKE.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `KDF` | `Pick`<[`KDF`](../interfaces/KDF.md), `"Derive"`> |
| `suite_id` | `Uint8Array` |
| `ikm` | `Uint8Array` |
| `label` | `Uint8Array` |
| `context` | `Uint8Array` |
| `L` | `number` |

## Returns

`Promise`<`Uint8Array`>
