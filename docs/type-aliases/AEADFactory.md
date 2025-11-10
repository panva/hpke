# Type Alias: AEADFactory()

> **AEADFactory** = () => `Readonly`<[`AEAD`](../interfaces/AEAD.md)>

Factory function that returns an AEAD implementation.

> \[!TIP]\
> [CipherSuite](../classes/CipherSuite.md) is not limited to using only these exported AEAD implementations. Any function
> returning an object conforming to the [AEAD](../interfaces/AEAD.md) interface can be used.

The following [Web Cryptography](https://www.w3.org/TR/webcrypto-2/)-based implementations are
exported by this module:

- [AES-128-GCM](../variables/AEAD_AES_128_GCM.md)
- [AES-256-GCM](../variables/AEAD_AES_256_GCM.md)
- [ChaCha20Poly1305](../variables/AEAD_ChaCha20Poly1305.md)
- [Export-only](../variables/AEAD_EXPORT_ONLY.md)

## Returns

`Readonly`<[`AEAD`](../interfaces/AEAD.md)>
