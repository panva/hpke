# Variable: KEM\_MLKEM1024\_P384

> `const` **KEM\_MLKEM1024\_P384**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Hybrid KEM combining ML-KEM-1024 with P-384 (MLKEM1024-P384).

Depends on the following Web API algorithms being supported in the runtime:

- ML-KEM-1024 key encapsulation
- ECDH with P-384 curve
- SHA3-256 digest
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion to

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
