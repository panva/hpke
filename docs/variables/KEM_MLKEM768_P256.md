# Variable: KEM\_MLKEM768\_P256

> `const` **KEM\_MLKEM768\_P256**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Hybrid KEM combining ML-KEM-768 with P-256 (MLKEM768-P256).

Depends on the following Web API algorithms being supported in the runtime:

- ML-KEM-768 key encapsulation
- ECDH with P-256 curve
- SHA3-256 digest
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion to

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
