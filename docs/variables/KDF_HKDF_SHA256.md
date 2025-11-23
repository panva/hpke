# Variable: KDF\_HKDF\_SHA256

> `const` **KDF\_HKDF\_SHA256**: [`KDFFactory`](../type-aliases/KDFFactory.md)

HKDF-SHA256 key derivation function.

A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-256 as the
hash function with an output length (Nh) of 32 bytes.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- HMAC with SHA-256

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
