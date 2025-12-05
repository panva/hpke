# Function: I2OSP()

> **I2OSP**(`n`, `w`): `Uint8Array`

Integer to Octet String Primitive (I2OSP) as defined in RFC 8017. Converts a non-negative integer
into a byte string of specified length. It's exported for use in custom KEM, KDF, or AEAD
implementations.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `n` | `number` | Non-negative safe integer to convert |
| `w` | `number` | Desired length of output in bytes |

## Returns

`Uint8Array`

A Uint8Array of length w containing the big-endian representation of n
