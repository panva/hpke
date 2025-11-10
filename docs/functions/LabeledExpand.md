# Function: LabeledExpand()

> **LabeledExpand**(`KDF`, `suite_id`, `prk`, `label`, `info`, `L`): `Promise`<`Uint8Array`>

Performs labeled expansion for two-stage KDFs.

This function implements the LabeledExpand operation as specified in the HPKE specification for
use with two-stage KDFs. It constructs a labeled info string by concatenating:

- The desired output length as a 2-byte encoding
- The version string "HPKE-v1"
- The suite identifier (`suite_id`)
- The label
- Additional info context

The labeled info is then passed to the KDF's Expand function along with the pseudorandom key to
produce L bytes of output keying material. This ensures domain separation between different uses
of the KDF in HPKE.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `KDF` | `Pick`<[`KDF`](../interfaces/KDF.md), `"Expand"`> |
| `suite_id` | `Uint8Array` |
| `prk` | `Uint8Array` |
| `label` | `Uint8Array` |
| `info` | `Uint8Array` |
| `L` | `number` |

## Returns

`Promise`<`Uint8Array`>
