# Type Alias: KDFFactory()

> **KDFFactory** = () => `Readonly`<[`KDF`](../interfaces/KDF.md)>

Factory function that returns a KDF implementation.

The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
exported by this module:

- [HKDF-SHA256](../variables/KDF_HKDF_SHA256.md)
- [HKDF-SHA384](../variables/KDF_HKDF_SHA384.md)
- [HKDF-SHA512](../variables/KDF_HKDF_SHA512.md)
- [SHAKE128](../variables/KDF_SHAKE128.md)
- [SHAKE256](../variables/KDF_SHAKE256.md)

> \[!TIP]\
> [CipherSuite](../classes/CipherSuite.md) is not limited to using only these exported KDF implementations. Any function
> returning an object conforming to the [KDF](../interfaces/KDF.md) interface can be used. Such implementations not
> reliant on Web Cryptography are exported by
> [`@panva/hpke-noble`](https://www.npmjs.com/package/@panva/hpke-noble)

## Returns

`Readonly`<[`KDF`](../interfaces/KDF.md)>
