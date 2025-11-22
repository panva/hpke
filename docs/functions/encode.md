# Function: encode()

> **encode**(`string`): `Uint8Array`

Encodes an ASCII string into a Uint8Array.

This utility function converts ASCII strings to byte arrays. It's exported for use in custom KEM,
KDF, or AEAD implementations.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `string` | `string` | ASCII string to encode |

## Returns

`Uint8Array`

A Uint8Array containing the ASCII byte values
