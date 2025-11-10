# Function: LabeledExtract()

> **LabeledExtract**(`KDF`, `suite_id`, `salt`, `label`, `ikm`): `Promise`<`Uint8Array`>

Performs labeled extraction for two-stage KDFs.

This function implements the LabeledExtract operation as specified in the HPKE specification for
use with two-stage KDFs. It constructs a labeled input by concatenating:

- The version string "HPKE-v1"
- The suite identifier (`suite_id`)
- The label
- The input keying material (`ikm`)

The labeled input is then passed to the KDF's Extract function along with the salt to produce a
pseudorandom key. This ensures domain separation between different uses of the KDF in HPKE.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `KDF` | `Pick`<[`KDF`](../interfaces/KDF.md), `"Extract"`> |
| `suite_id` | `Uint8Array` |
| `salt` | `Uint8Array` |
| `label` | `Uint8Array` |
| `ikm` | `Uint8Array` |

## Returns

`Promise`<`Uint8Array`>
