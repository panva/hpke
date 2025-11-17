# Variable: KEM\_DHKEM\_P256\_HKDF\_SHA256

> `const` **KEM\_DHKEM\_P256\_HKDF\_SHA256**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using NIST P-256 curve and HKDF-SHA256.

A Diffie-Hellman based KEM using the NIST P-256 elliptic curve (also known as secp256r1) with
HKDF-SHA256 for key derivation.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ECDH with P-256 curve
- HMAC with SHA-256 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
