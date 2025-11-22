# @panva/hpke-noble

`@panva/hpke-noble` provides additional HPKE algorithm implementations for use with [`@panva/hpke`](https://github.com/panva/hpke), using Paul Miller's [@noble](https://paulmillr.com/noble/) cryptographic libraries. This package provides cross-runtime support for algorithms not available in Web Cryptography, including post-quantum KEMs, SHAKE-based KDFs, and ChaCha20Poly1305 AEAD.

## Overview

`@panva/hpke-noble` provides additional algorithms for `@panva/hpke` by conforming to the HPKE interfaces ([KEM](../../docs/interfaces/KEM.md), [KDF](../../docs/interfaces/KDF.md), [AEAD](../../docs/interfaces/AEAD.md)). This approach allows you to:

- Use cryptographic primitives not available in Web Cryptography
- Support algorithms across all JavaScript runtimes (Node.js, browsers, Deno, Bun, Cloudflare Workers, etc.)
- Integrate specialized or audited cryptographic libraries

All implementations in this package work across all Web-interoperable JavaScript runtimes.

## Included Implementations

See [https://panva.github.io/hpke/](https://panva.github.io/hpke/?noble)

### KEM

| Name                       | ID       |
| -------------------------- | -------- |
| DHKEM(P-256, HKDF-SHA256)  | `0x0010` |
| DHKEM(P-384, HKDF-SHA384)  | `0x0011` |
| DHKEM(P-521, HKDF-SHA512)  | `0x0012` |
| DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| DHKEM(X448, HKDF-SHA512)   | `0x0021` |
| ML-KEM-512                 | `0x0040` |
| ML-KEM-768                 | `0x0041` |
| ML-KEM-1024                | `0x0042` |
| MLKEM768-X25519            | `0x647a` |

### KDF

| Name          | ID       |
| ------------- | -------- |
| HKDF-SHA256   | `0x0001` |
| HKDF-SHA384   | `0x0002` |
| HKDF-SHA512   | `0x0003` |
| SHAKE128      | `0x0010` |
| SHAKE256      | `0x0011` |
| TurboSHAKE128 | `0x0012` |
| TurboSHAKE256 | `0x0013` |

### AEAD

| Name             | ID       |
| ---------------- | -------- |
| AES-128-GCM      | `0x0001` |
| AES-256-GCM      | `0x0002` |
| ChaCha20Poly1305 | `0x0003` |

## Usage

Each implementation follows the factory pattern required by `@panva/hpke`:

```ts
import * as HPKE from '@panva/hpke'
import { KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305 } from '@panva/hpke-noble'

const suite = new HPKE.CipherSuite(KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305)
```

> [!NOTE]\n
> Built-in implementations (based on Web Cryptography) and `@panva/hpke-noble` implementations can be freely mixed and matched. For example, you could use `KEM_ML_KEM_768` from `@panva/hpke-noble` with `KDF_HKDF_SHA256` and `AEAD_AES_256_GCM` from `@panva/hpke`.

> [!NOTE]\
> These implementations are tested using the same test vectors and validation suite as the built-in implementations in `@panva/hpke`, ensuring correctness and interoperability.

## Example Integration

This package also serves as an example of how to integrate external cryptographic libraries with `@panva/hpke`. If you need to bring your own cryptographic primitives (e.g., hardware-backed implementations, audited libraries, or runtime-specific bindings), you can follow the same pattern by implementing the [KEM](../../docs/interfaces/KEM.md), [KDF](../../docs/interfaces/KDF.md), or [AEAD](../../docs/interfaces/AEAD.md) interfaces.
