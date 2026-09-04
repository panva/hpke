# Variable: KEM\_MLKEM1024\_P384

> `const` **KEM\_MLKEM1024\_P384**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Hybrid KEM combining ML-KEM-1024 with P-384 (MLKEM1024-P384).

Depends on one of the following Web Cryptography algorithm sets being supported in the runtime:

- MLKEM1024-P384 key encapsulation
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for key derivation

Or:

- ML-KEM-1024 key encapsulation
- ECDH with P-384 curve
- SHA3-256 digest
- SHAKE256 (cSHAKE256 without any parameters) digest on the recipient side for key derivation and
  composite-key seed expansion

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## See

[HPKE-PQ Hybrid KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05.html#section-4)
