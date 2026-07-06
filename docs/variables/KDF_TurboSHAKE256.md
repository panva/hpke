# Variable: KDF\_TurboSHAKE256

> `const` **KDF\_TurboSHAKE256**: [`KDFFactory`](../type-aliases/KDFFactory.md)

TurboSHAKE256 key derivation function.

A one-stage KDF using the TurboSHAKE256 extendable-output function (XOF) with an output length
(Nh) of 64 bytes.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- TurboSHAKE256 digest

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## See

[HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05.html#section-5)
