# Variable: KEM\_DHKEM\_X25519\_HKDF\_SHA256

> `const` **KEM\_DHKEM\_X25519\_HKDF\_SHA256**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using Curve25519 and HKDF-SHA256.

A Diffie-Hellman based KEM using the X25519 elliptic curve (Curve25519 for ECDH) with HKDF-SHA256
for key derivation.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- X25519 key agreement
- HMAC with SHA-256 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
