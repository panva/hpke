# Variable: KDF\_SHAKE256

> `const` **KDF\_SHAKE256**: [`KDFFactory`](../type-aliases/KDFFactory.md)

SHAKE256 key derivation function.

A one-stage KDF using the SHAKE256 extendable-output function (XOF) with an output length (Nh) of
64 bytes.

Depends on the following Web API algorithms being supported in the runtime:

- SHAKE256 (cSHAKE256 without any parameters) digest

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
