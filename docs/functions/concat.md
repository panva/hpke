# Function: concat()

> **concat**(...`buffers`): `Uint8Array`

Concatenates multiple Uint8Array buffers into a single Uint8Array. It's exported for use in
custom KEM, KDF, or AEAD implementations.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| ...`buffers` | `Uint8Array`\[] | Variable number of Uint8Array buffers to concatenate |

## Returns

`Uint8Array`

A new Uint8Array containing all input buffers concatenated in order
