# Variable: KEM\_ML\_KEM\_1024

> `const` **KEM\_ML\_KEM\_1024**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-1024).

A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ML-KEM-1024 key encapsulation
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient for key derivation

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
