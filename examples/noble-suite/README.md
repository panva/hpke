# Noble Suite Example

This example demonstrates how to use `@panva/hpke` with additional suites using custom cryptographic primitives, in this case using Paul Miller's [@noble](https://paulmillr.com/noble/) cryptographic libraries.

## Overview

The noble-suite example shows how to integrate alternative cryptographic implementations by conforming to the HPKE interfaces ([KEM](../../docs/interfaces/KEM.md), [KDF](../../docs/interfaces/KDF.md), [AEAD](../../docs/interfaces/AEAD.md)). This approach allows you to:

- Use cryptographic primitives not available in Web Cryptography
- Support algorithms across different runtime environments
- Integrate specialized or audited cryptographic libraries

## Included Implementations

### KEM (Key Encapsulation Mechanisms)

- **ML-KEM-512** - NIST standardized post-quantum KEM (via `@noble/post-quantum ^0.5.2`)
- **ML-KEM-768** - NIST standardized post-quantum KEM (via `@noble/post-quantum ^0.5.2`)
- **ML-KEM-1024** - NIST standardized post-quantum KEM (via `@noble/post-quantum ^0.5.2`)
- **MLKEM768-X25519** - Hybrid post-quantum/traditional KEM (aka X-Wing, via `@noble/post-quantum ^0.5.2`)

### KDF (Key Derivation Functions)

- **SHAKE128** - SHA-3 XOF-based KDF (via `@noble/hashes ^2.0.0`)
- **SHAKE256** - SHA-3 XOF-based KDF (via `@noble/hashes ^2.0.0`)
- **TurboSHAKE128** - High-performance SHA-3 variant (via `@noble/hashes ^2.0.0`)
- **TurboSHAKE256** - High-performance SHA-3 variant (via `@noble/hashes ^2.0.0`)

### AEAD (Authenticated Encryption with Associated Data)

- **ChaCha20Poly1305** - Modern authenticated encryption (via `@noble/ciphers ^2.0.0`)

## File Structure

- `index.ts` - Main entry point that exports all implementations
- `kem.ts` - Post-quantum and hybrid KEM implementations
- `kdf.ts` - SHA-3 based KDF implementations
- `aead.ts` - ChaCha20Poly1305 AEAD implementation

## Usage Pattern

Each implementation follows the factory pattern required by `@panva/hpke`:

```ts
import * as HPKE from '@panva/hpke'
import { KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305 } from './noble-suite/index.ts'

const suite = new HPKE.CipherSuite(KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305)
```

> [!NOTE]\
> Built-in implementations (based on Web Cryptography) and external implementations (like these using the @noble libraries) can be freely mixed and matched. For example, you could use `KEM_ML_KEM_768` from this example with `HPKE.KDF_HKDF_SHA256` and `HPKE.AEAD_AES_256_GCM` from the built-ins.

> [!NOTE]\
> These implementations are tested using the same test vectors and validation suite as the built-in implementations exposed by `@panva/hpke`, ensuring consistent correctness and interoperability.
