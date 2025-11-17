# Variable: AEAD\_ChaCha20Poly1305

> `const` **AEAD\_ChaCha20Poly1305**: [`AEADFactory`](../type-aliases/AEADFactory.md)

ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).

Uses ChaCha20 stream cipher with Poly1305 MAC.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ChaCha20-Poly1305 encryption and decryption

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
