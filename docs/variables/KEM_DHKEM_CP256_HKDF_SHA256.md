# Variable: KEM\_DHKEM\_CP256\_HKDF\_SHA256

> `const` **KEM\_DHKEM\_CP256\_HKDF\_SHA256**: [`KEMFactory`](../type-aliases/KEMFactory.md)

Diffie-Hellman Key Encapsulation Mechanism using compact NIST P-256 representation and
HKDF-SHA256.

This KEM is cryptographically identical to [KEM\_DHKEM\_P256\_HKDF\_SHA256](KEM_DHKEM_P256_HKDF_SHA256.md), but serializes
public keys and encapsulated secrets as the x-coordinate only.

Depends on the following Web Cryptography algorithms being supported in the runtime:

- ECDH with P-256 curve
- HMAC with SHA-256 (for HKDF)

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.

> \[!TIP]\
> An implementation of this algorithm not reliant on Web Cryptography is also exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## See

[DNHPKE Compact Representation](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.1)
