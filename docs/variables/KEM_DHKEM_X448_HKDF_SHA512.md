# Variable: KEM\_DHKEM\_X448\_HKDF\_SHA512

> `const` **KEM\_DHKEM\_X448\_HKDF\_SHA512**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using Curve448 and HKDF-SHA512.

A Diffie-Hellman based KEM using the X448 elliptic curve (Curve448 for ECDH) with HKDF-SHA512 for
key derivation.

Depends on the following Web API algorithms being supported in the runtime:

- X448 key agreement
- HMAC with SHA-512 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
