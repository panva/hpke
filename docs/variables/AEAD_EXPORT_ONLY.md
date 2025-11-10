# Variable: AEAD\_EXPORT\_ONLY

> `const` **AEAD\_EXPORT\_ONLY**: [`AEADFactory`](../type-aliases/AEADFactory.md)

Export-only AEAD mode.

A special AEAD mode that disables encryption/decryption operations and only allows key export
functionality. Used when HPKE is employed solely for key agreement and derivation, not for
message encryption. Cannot be used with Seal/Open operations.

This is a factory function that must be passed to the [CipherSuite](../classes/CipherSuite.md) constructor.
