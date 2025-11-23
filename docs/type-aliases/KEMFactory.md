# Type Alias: KEMFactory()

> **KEMFactory** = () => `Readonly`<[`KEM`](../interfaces/KEM.md)>

Factory function that returns a KEM implementation.

The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
exported by this module:

Traditional:

- [DHKEM(P-256, HKDF-SHA256)](../variables/KEM_DHKEM_P256_HKDF_SHA256.md)
- [DHKEM(P-384, HKDF-SHA384)](../variables/KEM_DHKEM_P384_HKDF_SHA384.md)
- [DHKEM(P-521, HKDF-SHA512)](../variables/KEM_DHKEM_P521_HKDF_SHA512.md)
- [DHKEM(X25519, HKDF-SHA256)](../variables/KEM_DHKEM_X25519_HKDF_SHA256.md)
- [DHKEM(X448, HKDF-SHA512)](../variables/KEM_DHKEM_X448_HKDF_SHA512.md)

Post-quantum/Traditional (PQ/T Hybrid):

- [MLKEM768-P256](../variables/KEM_MLKEM768_P256.md)
- [MLKEM768-X25519 (aka X-Wing)](../variables/KEM_MLKEM768_X25519.md)
- [MLKEM1024-P384](../variables/KEM_MLKEM1024_P384.md)

Post-quantum (PQ):

- [ML-KEM-512](../variables/KEM_ML_KEM_512.md)
- [ML-KEM-768](../variables/KEM_ML_KEM_768.md)
- [ML-KEM-1024](../variables/KEM_ML_KEM_1024.md)

> \[!TIP]\
> [CipherSuite](../classes/CipherSuite.md) is not limited to using only these exported KEM implementations. Any function
> returning an object conforming to the [KEM](../interfaces/KEM.md) interface can be used. Such implementations not
> reliant on Web Cryptography are exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## Returns

`Readonly`<[`KEM`](../interfaces/KEM.md)>
