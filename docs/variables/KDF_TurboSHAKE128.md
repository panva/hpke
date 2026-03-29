# Variable: KDF\_TurboSHAKE128

> `const` **KDF\_TurboSHAKE128**: [`KDFFactory`](../type-aliases/KDFFactory.md)

TurboSHAKE128 key derivation function.

A one-stage KDF using the TurboSHAKE128 extendable-output function (XOF) with an output length
(Nh) of 32 bytes.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- TurboSHAKE128 digest

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## See

[HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-5)
