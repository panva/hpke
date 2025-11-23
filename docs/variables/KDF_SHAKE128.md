# Variable: KDF\_SHAKE128

> `const` **KDF\_SHAKE128**: [`KDFFactory`](../type-aliases/KDFFactory.md)

SHAKE128 key derivation function.

A one-stage KDF using the SHAKE128 extendable-output function (XOF) with an output length (Nh) of
32 bytes.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- SHAKE128 (cSHAKE128 without any parameters) digest

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
