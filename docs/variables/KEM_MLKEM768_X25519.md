# Variable: KEM\_MLKEM768\_X25519

> `const` **KEM\_MLKEM768\_X25519**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Hybrid KEM combining ML-KEM-768 with X25519 (MLKEM768-X25519 aka X-Wing).

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ML-KEM-768 key encapsulation
- X25519 key agreement
- SHA3-256 digest
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for seed expansion

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)
