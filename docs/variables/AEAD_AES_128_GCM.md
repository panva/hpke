# Variable: AEAD\_AES\_128\_GCM

> `const` **AEAD\_AES\_128\_GCM**: [`AEADFactory`](../type-aliases/AEADFactory.md)

AES-128-GCM Authenticated Encryption with Associated Data (AEAD).

Uses AES in Galois/Counter Mode with 128-bit keys.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- AES-GCM encryption and decryption

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
