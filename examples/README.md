# Examples

This directory contains practical examples demonstrating various features and use cases of `hpke`.

## Basic Examples

### [01-basic.ts](01-basic.ts)

Basic message exchange with authenticated additional data (AAD). Demonstrates:

- Key pair generation
- Public key serialization/deserialization
- Setting up sender and recipient contexts
- Encrypting and decrypting multiple messages with AAD

### [02-psk-mode.ts](02-psk-mode.ts)

Pre-shared key (PSK) mode for authenticated encryption. Demonstrates:

- Using PSK mode for additional authentication
- How to provide PSK and PSK identifier
- Verifying the context mode

### [03-exporter.ts](03-exporter.ts)

Exporting derived secrets from HPKE contexts. Demonstrates:

- Using the `Export()` method to derive additional keys
- Both sender and recipient deriving the same secrets
- Use cases for exported secrets (additional keys, MACs, session IDs)

### [04-single-shot.ts](04-single-shot.ts)

Single-shot encryption/decryption API. Demonstrates:

- `Seal()` and `Open()` for one-time encryption
- When to use single-shot vs context-based encryption
- Simpler API for single message scenarios

## Advanced Examples

### [05-derive-keypair.ts](05-derive-keypair.ts)

Deterministic key pair derivation. Demonstrates:

- Deriving key pairs from input keying material (IKM)
- Reproducible key generation
- Use cases: key backup, recovery, deterministic testing

### [06-export-only-mode.ts](06-export-only-mode.ts)

Export-only AEAD mode for key agreement. Demonstrates:

- Using `AEAD_EXPORT_ONLY` when encryption is not needed
- Pure key agreement without encryption overhead
- Use cases: deriving session keys for external protocols

## External Library Integration

### [noble-suite/](noble-suite/)

Integrating external cryptographic libraries. Demonstrates:

- Implementing custom KEM, KDF, and AEAD algorithms
- Using the [@noble](https://paulmillr.com/noble/) cryptographic libraries
- Making algorithms available across different runtimes where built-ins aren't supported yet
- See [noble-suite/README.md](noble-suite/README.md) for details

## Running Examples

All examples can be run directly with Node.js

```bash
git clone https://github.com/panva/hpke.git
cd hpke
node examples/01-basic.ts
```
