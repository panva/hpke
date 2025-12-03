# hpke

`hpke` is a JavaScript module for Hybrid Public Key Encryption (HPKE). This module is designed to
work across various Web-interoperable runtimes including Node.js, browsers, Cloudflare Workers,
Deno, Bun, and others.

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find
this module useful, please consider supporting this project by
[becoming a sponsor](https://github.com/sponsors/panva).

## Dependencies: 0

`hpke` has no dependencies and it exports tree-shakeable ESM.

## [API Reference](docs/README.md)

`hpke` is distributed via [npmjs.com](https://www.npmjs.com/package/hpke),
[jsdelivr.com](https://www.jsdelivr.com/package/npm/hpke), and
[github.com](https://github.com/panva/hpke).

## Quick Start

```ts
import * as HPKE from 'hpke'

// 1. Choose a cipher suite
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

// 2. Generate recipient key pair
const recipient = await suite.GenerateKeyPair()

// 3. Encrypt a message
const plaintext = new TextEncoder().encode('Hello, World!')
const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext)

// 4. Decrypt the message
const decrypted = await suite.Open(recipient.privateKey, encapsulatedSecret, ciphertext)
console.log(new TextDecoder().decode(decrypted)) // "Hello, World!"
```

## [Examples](examples/README.md)

For more advanced examples, including how to integrate external cryptographic libraries, see the
[examples directory](examples/README.md).

## Supported Runtimes

This module is compatible with JavaScript runtimes that support the utilized Web API globals and
standard built-in objects or are Node.js.

The following runtimes are supported _(this is not an exhaustive list)_:

- Bun
- Browsers
- Cloudflare Workers
- Deno
- Electron
- Node.js

Please note that some suites may not be available depending on the runtime used.

## Supported Algorithms

Algorithm implementations exposed by this module are built on top of [Web Cryptography][] (and its
extensions, e.g. [Secure Curves][], [Modern Algorithms][]). Runtimes implementing Web Cryptography
are not required to support all of its algorithms and so not all algorithms are available in all
runtimes.

This module is designed to be extensible, you can bring outside-built implementations of any KEM,
KDF, or AEAD algorithm into any JavaScript runtime by conforming to the respective interfaces
([KEM](https://github.com/panva/hpke/blob/main/docs/interfaces/KEM.md),
[KDF](https://github.com/panva/hpke/blob/main/docs/interfaces/KDF.md), or
[AEAD](https://github.com/panva/hpke/blob/main/docs/interfaces/AEAD.md)). This allows you to use
alternative cryptographic libraries, native bindings, or specialized hardware implementations
alongside the built-in Web Cryptography-based algorithms.

For extended algorithm support across all runtimes, see [`@panva/hpke-noble`][extensibility], which
provides these KEM, KDF, and AEAD implementations using Paul Miller's
[@noble](https://paulmillr.com/noble/) cryptographic libraries. These implementations can be freely
mixed and matched with the built-in algorithms.

Below are the algorithms built in (based on Web Cryptography) and their runtime support matrix.

### Key Encapsulation Mechanisms (KEM)

| Name                                           | Node.js  | Deno | Bun | CF Workers | [Browsers][] | [Extensibility][] |
| :--------------------------------------------- | :------: | :--: | :-: | :--------: | :----------: | :---------------: |
| DHKEM(P-256, HKDF-SHA256) <sub>`0x0010`</sub>  |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| DHKEM(P-384, HKDF-SHA384) <sub>`0x0011`</sub>  |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| DHKEM(P-521, HKDF-SHA512) <sub>`0x0012`</sub>  |    ✓     |      |  ✓  |     ✓      |      ✓       |         ✓         |
| DHKEM(X25519, HKDF-SHA256) <sub>`0x0020`</sub> |    ✓     |  ✓   |     |     ✓      |      ✓       |         ✓         |
| DHKEM(X448, HKDF-SHA512) <sub>`0x0021`</sub>   |    ✓     |      |     |            |              |         ✓         |
| ML-KEM-512 <sub>`0x0040`</sub>                 | ✓[^24.7] |      |     |            |              |         ✓         |
| ML-KEM-768 <sub>`0x0041`</sub>                 | ✓[^24.7] |      |     |            |              |         ✓         |
| ML-KEM-1024 <sub>`0x0042`</sub>                | ✓[^24.7] |      |     |            |              |         ✓         |
| MLKEM768-P256 <sub>`0x0050`</sub>              | ✓[^24.7] |      |     |            |              |         ✓         |
| MLKEM768-X25519 <sub>`0x647a`</sub>            | ✓[^24.7] |      |     |            |              |         ✓         |
| MLKEM1024-P384 <sub>`0x0051`</sub>             | ✓[^24.7] |      |     |            |              |         ✓         |

### Key Derivation Functions (KDF)

| Name                              | Node.js  | Deno | Bun | CF Workers | [Browsers][] | [Extensibility][] |
| :-------------------------------- | :------: | :--: | :-: | :--------: | :----------: | :---------------: |
| HKDF-SHA256 <sub>`0x0001`</sub>   |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| HKDF-SHA384 <sub>`0x0002`</sub>   |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| HKDF-SHA512 <sub>`0x0003`</sub>   |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| SHAKE128 <sub>`0x0010`</sub>      | ✓[^24.7] |      |     |            |              |         ✓         |
| SHAKE256 <sub>`0x0011`</sub>      | ✓[^24.7] |      |     |            |              |         ✓         |
| TurboSHAKE128 <sub>`0x0012`</sub> |          |      |     |            |              |         ✓         |
| TurboSHAKE256 <sub>`0x0013`</sub> |          |      |     |            |              |         ✓         |

### Authenticated Encryption (AEAD)

| Name                                 | Node.js  | Deno | Bun | CF Workers | [Browsers][] | [Extensibility][] |
| :----------------------------------- | :------: | :--: | :-: | :--------: | :----------: | :---------------: |
| AES-128-GCM <sub>`0x0001`</sub>      |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| AES-256-GCM <sub>`0x0002`</sub>      |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |         ✓         |
| ChaCha20Poly1305 <sub>`0x0003`</sub> | ✓[^24.7] |      |     |            |              |         ✓         |
| Export-only <sub>`0xffff`</sub>      |    ✓     |  ✓   |  ✓  |     ✓      |      ✓       |                   |

## Specifications

- [Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02)
- [Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03)

The algorithm implementations are being tested using test vectors from their respective
specifications.

## Supported Versions

| Version                                         | Security Fixes 🔑 | Other Bug Fixes 🐞 | New Features ⭐ |
| ----------------------------------------------- | ----------------- | ------------------ | --------------- |
| [v1.x](https://github.com/panva/hpke/tree/v1.x) | [Security Policy] | ✓                  | ✓               |

[Web Cryptography]: https://www.w3.org/TR/webcrypto-2/
[Security Policy]: https://github.com/panva/hpke/security/policy
[Secure Curves]: https://wicg.github.io/webcrypto-secure-curves/
[Modern Algorithms]: https://wicg.github.io/webcrypto-modern-algos/
[extensibility]: https://github.com/panva/hpke/tree/main/examples/noble-suite#readme
[browsers]: https://panva.github.io/hpke/

[^24.7]: Available in Node.js versions >= 24.7.0
