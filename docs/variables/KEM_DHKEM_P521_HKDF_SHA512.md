# Variable: KEM\_DHKEM\_P521\_HKDF\_SHA512

> `const` **KEM\_DHKEM\_P521\_HKDF\_SHA512**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using NIST P-521 curve and HKDF-SHA512.

A Diffie-Hellman based KEM using the NIST P-521 elliptic curve (also known as secp521r1) with
HKDF-SHA512 for key derivation.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ECDH with P-521 curve
- HMAC with SHA-512 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
