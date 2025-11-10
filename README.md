# @panva/hpke

`@panva/hpke` is a JavaScript module for Hybrid Public Key Encryption (HPKE). This module is designed to work across various Web-interoperable runtimes including Node.js, browsers, Cloudflare Workers, Deno, Bun, and others.

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find this module useful, please consider supporting this project by [becoming a sponsor](https://github.com/sponsors/panva).

## Dependencies: 0

`@panva/hpke` has no dependencies and it exports tree-shakeable ESM[^cjs].

## [API Reference](docs/README.md)

`@panva/hpke` is distributed via [npmjs.com](https://www.npmjs.com/package/@panva/hpke), [jsdelivr.com](https://www.jsdelivr.com/package/npm/@panva/hpke), and [github.com](https://github.com/panva/hpke).

## Quick Start

```ts
import * as HPKE from '@panva/hpke'

// 1. Choose a cipher suite
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// 2. Generate recipient key pair
const recipientKeyPair = await suite.GenerateKeyPair()

// 3. Encrypt a message
const plaintext = new TextEncoder().encode('Hello, World!')
const { encapsulated_key, ciphertext } = await suite.Seal(recipientKeyPair.publicKey, plaintext)

// 4. Decrypt the message
const decrypted = await suite.Open(recipientKeyPair, encapsulated_key, ciphertext)
console.log(new TextDecoder().decode(decrypted)) // "Hello, World!"
```

## [Examples](examples/README.md)

For more advanced examples, including how to integrate external cryptographic libraries, see the [examples directory](examples/README.md).

## Supported Runtimes

This module is compatible with JavaScript runtimes that support the utilized Web API globals and standard built-in objects or are Node.js.

The following runtimes are supported _(this is not an exhaustive list)_:

- Bun
- Browsers
- Cloudflare Workers
- Deno
- Electron
- Node.js

Please note that some suites may not be available depending on the runtime used.

## Supported Algorithms

Algorithm implementations exposed by this module are built on top of [Web Cryptography][] (and its extensions, e.g. [Secure Curves][], [Modern Algorithms][]). Runtimes implementing Web Cryptography are not required to support all of its algorithms and so not all algorithms are available in all runtimes.

This module is designed to be extensible, you can bring outside-built implementations of any KEM, KDF, or AEAD algorithm into any runtime by conforming to the respective interfaces ([KEM](docs/interfaces/KEM.md), [KDF](docs/interfaces/KDF.md), [AEAD](docs/interfaces/AEAD.md)). This allows you to use alternative cryptographic libraries, native bindings, or specialized hardware implementations alongside the built-in Web Cryptography-based algorithms. See the [Noble Suite Example](examples/noble-suite/) for a demonstration of integrating external cryptographic libraries. Below are the algorithms built in (based on Web Cryptography) and their runtime support matrix.

### KEM

| Name                       | ID       | Node.js  | Deno | Bun | Cloudflare Workers | Browsers |
| -------------------------- | -------- | -------- | ---- | --- | ------------------ | -------- |
| DHKEM(P-256, HKDF-SHA256)  | `0x0010` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| DHKEM(P-384, HKDF-SHA384)  | `0x0011` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| DHKEM(P-521, HKDF-SHA512)  | `0x0012` | ✓        |      | ✓   | ✓                  | ✓        |
| DHKEM(X25519, HKDF-SHA256) | `0x0020` | ✓        | ✓    |     | ✓                  | ✓        |
| DHKEM(X448, HKDF-SHA512)   | `0x0021` | ✓        |      |     |                    |          |
| ML-KEM-512                 | `0x0040` | ✓[^24.7] |      |     |                    |          |
| ML-KEM-768                 | `0x0041` | ✓[^24.7] |      |     |                    |          |
| ML-KEM-1024                | `0x0042` | ✓[^24.7] |      |     |                    |          |
| MLKEM768-P256              | `0x0050` | ✓[^24.7] |      |     |                    |          |
| MLKEM768-X25519            | `0x647a` | ✓[^24.7] |      |     |                    |          |
| MLKEM1024-P384             | `0x0051` | ✓[^24.7] |      |     |                    |          |

### KDF

| Name        | ID       | Node.js  | Deno | Bun | Cloudflare Workers | Browsers |
| ----------- | -------- | -------- | ---- | --- | ------------------ | -------- |
| HKDF-SHA256 | `0x0001` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| HKDF-SHA384 | `0x0002` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| HKDF-SHA512 | `0x0003` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| SHAKE128    | `0x0010` | ✓[^24.7] |      |     |                    |          |
| SHAKE256    | `0x0011` | ✓[^24.7] |      |     |                    |          |

### AEAD

| Name             | ID       | Node.js  | Deno | Bun | Cloudflare Workers | Browsers |
| ---------------- | -------- | -------- | ---- | --- | ------------------ | -------- |
| AES-128-GCM      | `0x0001` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| AES-256-GCM      | `0x0002` | ✓        | ✓    | ✓   | ✓                  | ✓        |
| ChaCha20Poly1305 | `0x0003` | ✓[^24.7] |      |     |                    |          |
| Export-only      | `0xffff` | ✓        | ✓    | ✓   | ✓                  | ✓        |

## Supported Versions

| Version                                         | Security Fixes 🔑 | Other Bug Fixes 🐞 | New Features ⭐ |
| ----------------------------------------------- | ----------------- | ------------------ | --------------- |
| [v0.x](https://github.com/panva/hpke/tree/v0.x) | [Security Policy] | ✓                  | ✓               |

## Specifications

<details>
<summary>Details</summary>

- [Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02)
- [Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03)

The algorithm implementations in `@panva/hpke` have been tested using test vectors from their respective specifications.

</details>

[Web Cryptography]: https://www.w3.org/TR/webcrypto-2/
[Security Policy]: https://github.com/panva/hpke/security/policy
[Secure Curves]: https://wicg.github.io/webcrypto-secure-curves/
[Modern Algorithms]: https://wicg.github.io/webcrypto-modern-algos/

[^24.7]: Available in Node.js versions >= 24.7.0
