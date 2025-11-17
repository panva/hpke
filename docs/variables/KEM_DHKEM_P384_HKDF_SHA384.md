# Variable: KEM\_DHKEM\_P384\_HKDF\_SHA384

> `const` **KEM\_DHKEM\_P384\_HKDF\_SHA384**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using NIST P-384 curve and HKDF-SHA384.

A Diffie-Hellman based KEM using the NIST P-384 elliptic curve (also known as secp384r1) with
HKDF-SHA384 for key derivation.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ECDH with P-384 curve
- HMAC with SHA-384 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
