# Noble Suite Example

This example demonstrates how to use `@panva/hpke` with additional suites using custom cryptographic primitives, in this case using Paul Miller's [@noble](https://paulmillr.com/noble/) cryptographic libraries.

## Overview

The noble-suite example shows how to integrate alternative cryptographic implementations by conforming to the HPKE interfaces ([KEM](../../docs/interfaces/KEM.md), [KDF](../../docs/interfaces/KDF.md), [AEAD](../../docs/interfaces/AEAD.md)). This approach allows you to:

- Use cryptographic primitives not available in Web Cryptography
- Support algorithms across different runtime environments
- Integrate specialized or audited cryptographic libraries

## Included Implementations

### KEM (Key Encapsulation Mechanisms)

- DHKEM-P-256-HKDF-SHA256
- DHKEM-P-384-HKDF-SHA384
- DHKEM-P-521-HKDF-SHA512
- DHKEM-X25519-HKDF-SHA256
- DHKEM-X448-HKDF-SHA512
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024
- MLKEM768-X25519

### KDF (Key Derivation Functions)

- HKDF-SHA256
- HKDF-SHA384
- HKDF-SHA512
- SHAKE128
- SHAKE256
- TurboSHAKE128
- TurboSHAKE256

### AEAD (Authenticated Encryption with Associated Data)

- AES-128-GCM
- AES-256-GCM
- ChaCha20Poly1305

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
