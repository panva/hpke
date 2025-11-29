# Security Policy

## Supported Versions

The following major versions are currently supported with security updates.

| Version                                         | End-of-life                 |
| ----------------------------------------------- | --------------------------- |
| [v0.x](https://github.com/panva/hpke/tree/v0.x) | as soon as v1.x is released |

End-of-life for the current release will be determined prior to the release of its successor.

## Reporting a Vulnerability

You should report vulnerabilities using the [Github UI](https://github.com/panva/hpke/security/advisories/new) or via email panva.ip@gmail.com

## Threat Model

This section documents the threat model for `@panva/hpke` and `@panva/hpke-noble`. `@panva/hpke` is a JavaScript implementation of [Hybrid Public Key Encryption (draft-ietf-hpke-hpke)](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02) and [Post-Quantum/Traditional Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03). `@panva/hpke-noble` provides additional algorithm implementations using [@noble](https://paulmillr.com/noble/) cryptographic libraries.

### Purpose and Intended Users

This library is intended for general application developers, cryptography practitioners, and anyone needing HPKE functionality in JavaScript runtimes (Node.js, browsers, Cloudflare Workers, Deno, Bun, and other Web-interoperable environments).

### Trust Assumptions

#### Underlying Cryptographic Primitives

This library trusts that the Web Cryptography implementations provided by the runtime are correct and secure. The library delegates all cryptographic operations (key generation, encryption, decryption, key derivation, etc.) to the runtime's Web Cryptography implementation and does not attempt to validate or verify the correctness of these underlying primitives during runtime.

#### Runtime Environment

The library assumes it is running in a trusted execution environment. The following are considered outside the scope of this library's threat model:

- **Prototype pollution attacks**: If an attacker can modify JavaScript prototypes, this is considered a vulnerability in the user's application code or the runtime environment, not in this library.
- **Debugger access**: If an attacker has debugger access to the running process, they can inspect memory, modify variables, and bypass security controls. This is a runtime-level compromise, not a library vulnerability.
- **Runtime compromise**: Attacks that compromise the JavaScript runtime itself (e.g., malicious runtime modifications, compromised Node.js binaries, malicious browser extensions with elevated privileges) are not considered attacks on this library.

#### Side-Channel Attacks

This library delegates all cryptographic operations to the underlying Web Cryptography (or user-provided algorithm implementations). Any resistance to side-channel attacks (timing attacks, cache attacks, etc.) is entirely dependent on the underlying cryptographic implementations and is outside the scope of this library.

### Security Guarantees

This library aims to provide the following security guarantees:

- **Specification compliance**: Correct implementation of [Hybrid Public Key Encryption (HPKE)](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02) and [Post-Quantum/Traditional Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03), validated against test vectors from the respective specifications.
- **Nonce/sequence number handling**: Proper management of nonces and sequence numbers as required by the HPKE specification to prevent nonce reuse.
- **Input validation**: Validation of inputs to prevent misuse of the API.

### Out of Scope

#### Key Management

This library does not handle key storage. Users are responsible for securely storing, managing, and distributing cryptographic keys or input keying material.

#### Memory Clearing

This library does not guarantee that key material or other sensitive data is cleared from memory after use. As long as the user retains references to key objects, the key material may remain in memory. Secure memory management is the responsibility of the user and the runtime environment.

#### User-Provided Algorithm Implementations

This library supports extensibility by allowing users to provide their own KEM, KDF, or AEAD implementations. The security of user-provided implementations is entirely the user's responsibility. This library does not validate the correctness or security of user-provided algorithm implementations.

### Threat Actors and Security Properties

This library aims to provide the security properties defined by the HPKE specification. For a detailed analysis of threat models, security properties, and security considerations, refer to [Section 9 of HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-9).

### What is NOT Considered a Vulnerability

The following are explicitly **not** considered vulnerabilities in this library:

- **Prototype pollution** ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)): Attacks that exploit JavaScript prototype pollution are considered vulnerabilities in user application code or the runtime, not this library.
- **Object injection** ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)): Similar to prototype pollution, object injection attacks are outside the scope of this library.
- **Debugger/inspector access** ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)): If an attacker can attach a debugger to the process, they have already compromised the runtime environment.
- **Memory inspection**: Reading process memory, heap dumps, or core dumps to extract key material is a runtime-level attack.
- **Side-channel attacks** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)): Timing attacks, cache attacks, and other side-channel vulnerabilities in the underlying Web Cryptography implementations are not vulnerabilities in this library.
- **Compromised runtime environment**: Malicious or backdoored JavaScript runtimes, compromised system libraries, or tampered Web Cryptography implementations.
- **Supply chain attacks on the runtime** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): Compromised Node.js binaries, malicious browser builds, or similar supply chain attacks on the execution environment.
- **Supply chain attacks on third-party libraries** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): `@panva/hpke` has zero dependencies. `@panva/hpke-noble` depends on [@noble](https://paulmillr.com/noble/) cryptographic libraries. Supply chain compromises of third-party dependencies (including `@noble` libraries or any user-provided algorithm implementations) are not considered vulnerabilities in this project.
- **Denial of service via resource exhaustion** ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)): While the library validates inputs, it does not implement resource limits. Applications should implement their own rate limiting and resource management.
- **Issues in user-provided algorithm implementations**: Security flaws in custom KEM, KDF, or AEAD implementations provided by users are the user's responsibility.
