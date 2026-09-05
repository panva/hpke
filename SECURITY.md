# Security Policy

## Supported Versions

The following major versions are currently supported with security updates.

| Version                                         | End-of-life |
| ----------------------------------------------- | ----------- |
| [v1.x](https://github.com/panva/hpke/tree/v1.x) | TBD         |

End-of-life for the current release will be determined prior to the release of its successor.

## Reporting a Vulnerability

Vulnerabilities must be reported using the [project's security advisory](https://github.com/panva/hpke/security/advisories/new).

**All vulnerability reports MUST be submitted through the channel listed above.** This allows the maintainers to assess the report, collaborate on remediation, and coordinate disclosure in a responsible manner.

CVE identifiers for this project, whether for confirmed, rejected, disputed, or untriaged reports, may only be requested or coordinated by the maintainers, or with the maintainers' explicit consent, through the GitHub Security Advisory process. Submitting a report through the project's security advisory does not authorize reporters to request CVE identifiers from, disclose details to, or otherwise coordinate with third-party CVE Numbering Authorities (CNAs), such as MITRE, for this project.

If the maintainers reject a report through the project's documented channel, that rejection does not authorize the reporter to bypass the project's security disclosure process by pursuing a CVE assignment through a third-party CNA. The maintainers reserve the right to request rejection, withdrawal, or dispute of any CVE entry that was requested, assigned, or coordinated without prior explicit consent from the maintainers.

## Threat Model

This section documents the threat model for `hpke` and `@panva/hpke-noble`. `hpke` is a JavaScript implementation of the active standards-track drafts [Hybrid Public Key Encryption (draft-ietf-hpke-hpke-04)](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04) and [Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE (draft-ietf-hpke-pq-05)](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05). `@panva/hpke-noble` provides additional algorithm implementations using [@noble](https://paulmillr.com/noble/) cryptographic libraries.

These drafts are works in progress and may change before publication. This project tracks the active standards-track drafts rather than the older HPKE RFC 9180 API surface. In particular, only Base mode and PSK mode are implemented. The RFC 9180 Auth and AuthPSK modes are not implemented because they were removed from the active standards-track HPKE draft.

### Purpose and Intended Users

This library is intended for general application developers, cryptography practitioners, and anyone needing HPKE functionality in JavaScript runtimes (Node.js, browsers, Cloudflare Workers, Deno, Bun, and other Web-interoperable environments).

### Threat Actors

This threat model considers active network attackers that can observe, modify, replay, drop, reorder, and inject HPKE inputs such as serialized public keys, encapsulated secrets, ciphertexts, `info`, AAD, PSK identifiers, and application framing. The attacker may choose malformed inputs and observe application behavior unless the application normalizes failures.

The threat model does not include attackers that control the local application, the JavaScript runtime, the operating system, the underlying cryptographic implementation, or secret key storage.

### Trust Assumptions

#### Underlying Cryptographic Primitives

This library trusts that the Web Cryptography implementations provided by the runtime are correct and secure. The library delegates cryptographic primitive operations (key generation, public-key recovery, signature generation and verification, encryption, decryption, key agreement, KEM encapsulation and decapsulation, hashing, and key derivation) to the runtime's Web Cryptography implementation and does not attempt to validate or verify the correctness of these underlying primitives during runtime.

This library also trusts the runtime's cryptographically secure random number generator. Bad, predictable, repeated, or compromised ephemeral randomness can compromise HPKE confidentiality and can cause AEAD key/nonce reuse.

#### Runtime Environment

The library assumes it is running in a trusted execution environment. The following are considered outside the scope of this library's threat model:

- **Prototype pollution attacks**: If an attacker can modify JavaScript prototypes, this is considered a vulnerability in the user's application code or the runtime environment, not in this library.
- **Debugger access**: If an attacker has debugger access to the running process, they can inspect memory, modify variables, and bypass security controls. This is a runtime-level compromise, not a library vulnerability.
- **Runtime compromise**: Attacks that compromise the JavaScript runtime itself (e.g., malicious runtime modifications, compromised Node.js binaries, malicious browser extensions with elevated privileges) are not considered attacks on this library.

#### Side-Channel Attacks

This library delegates primitive cryptographic operations to the underlying Web Cryptography, `@noble`, or user-provided algorithm implementations. Any resistance to side-channel attacks (timing attacks, cache attacks, etc.) is dependent on those implementations and on the JavaScript runtime and is outside the scope of this library.

### Security Guarantees

This library aims to provide the following security guarantees:

- **Specification compliance**: Correct implementation of [draft-ietf-hpke-hpke-04](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04) and [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05), validated against test vectors from the respective specifications.
- **Base mode confidentiality**: Confidentiality and integrity for messages encrypted to a recipient public key, subject to the security of the chosen KEM, KDF, AEAD, runtime, and application embedding. Base mode does not authenticate the sender.
- **PSK mode authentication**: Implicit authentication that the sender possessed the configured PSK, subject to the PSK being high entropy, uncompromised, and correctly bound to the application's peer and protocol context. This library rejects PSKs shorter than 32 bytes but cannot validate entropy.
- **Nonce/sequence number handling**: Automatic per-context nonce derivation and sequence number management as required by the HPKE specification to prevent nonce reuse within a context. This implementation serializes concurrent context operations and supports sequence numbers up to `2^53-1`; applications should rotate contexts well before any AEAD-specific message or data-volume limit.
- **Input validation**: Validation of API input types, public and private key lengths, encapsulated secret lengths, PSK/PSK ID consistency, and KDF input lengths.

### Application Responsibilities and Non-Goals

#### Input Buffer Lifetimes

Applications must keep byte-array inputs unchanged until the operation's returned promise settles. This includes avoiding mutation through other views of the same backing buffer, as well as resizing or detaching that buffer. This library may read inputs across asynchronous steps and does not guarantee a snapshot when an operation starts. Concurrent input mutation by application code is outside this library's threat model.

#### Key Management

This library does not handle key storage. Users are responsible for securely storing, managing, and distributing cryptographic keys or input keying material.

Applications are responsible for recipient public key authenticity. Encrypting to an attacker-substituted public key is outside this library's ability to detect.

#### Message Order, Loss, and Replay

Applications using multi-message sender and recipient contexts must present ciphertexts to `Open` in the same order they were produced by `Seal`. Applications must detect lost messages and discard the affected HPKE context when unrecoverable loss is detected.

HPKE provides no replay protection beyond the ordering requirement within a single context. Applications that require replay protection must include suitable sequence numbers, transcript identifiers, channel identifiers, or other framing in the associated data and enforce replay policy themselves.

#### Algorithm Negotiation and Downgrade Prevention

Applications must agree on the KEM, KDF, AEAD, mode, recipient key, PSK identity, and any protocol context. If these values are negotiated or carried on the wire, the application must protect them against downgrade and substitution attacks, typically by binding them into authenticated framing or AAD.

#### Message Encoding and Associated Data

This library does not define a wire format. Applications must encode and authenticate, as appropriate, the encapsulated secret, ciphertext ordering, recipient key identifier, PSK ID, content type, protocol version, and other framing metadata.

AAD is only authenticated if the same bytes are provided to both `Seal` and `Open`. The application is responsible for deciding what protocol metadata belongs in AAD.

#### Error Handling and Oracles

This library exposes distinct error types and messages for developer diagnostics. These errors are not intended to be forwarded as protocol-level responses. Applications handling attacker-controlled encapsulated secrets, ciphertexts, PSK IDs, or key identifiers should map decryption and decapsulation failures to a single external failure response and avoid externally observable timing differences where feasible.

Externally distinguishing failures such as "unknown PSK ID", "bad encapsulated secret", "bad ciphertext or tag", "wrong suite", or "wrong recipient key" can create protocol or decryption oracles. With a low-entropy PSK, such an oracle can aid PSK recovery. With high-entropy PSKs, normalizing failures remains recommended to avoid unnecessary information disclosure.

#### Forward Secrecy and Compromise

HPKE ciphertexts are not forward secret with respect to recipient private key compromise. If a recipient private key is compromised, past Base mode ciphertexts encrypted to that key can be decrypted by an attacker. In PSK mode, confidentiality of past ciphertexts depends on the attacker not having both the recipient private key and the PSK.

#### Plaintext Length, Metadata, and Bidirectional Use

HPKE ciphertexts do not hide plaintext length. Applications requiring length privacy must add padding.

PSK IDs, recipient key identifiers, and other routing metadata may identify senders, recipients, tenants, or applications. This library does not hide such metadata.

HPKE is unidirectional. Applications that use exported secrets for bidirectional protocols are responsible for domain separation, independent keys and nonces, role separation, and message limits.

#### Post-Quantum Algorithms

The post-quantum and post-quantum/traditional hybrid algorithms implemented by this library follow an active Internet-Draft and depend on runtime support for the relevant Web Cryptography algorithms. Claims about post-quantum security are limited by the draft status, the maturity of the algorithms, the correctness of the runtime implementation, and future cryptanalysis.

ML-KEM-512 is included for completeness and interoperability. Applications should generally prefer ML-KEM-768, ML-KEM-1024, or the PQ/T hybrid KEMs unless they specifically need ML-KEM-512.

#### Memory Clearing

This library does not guarantee that key material or other sensitive data is cleared from memory after use. As long as the user retains references to key objects, the key material may remain in memory. Secure memory management is the responsibility of the user and the runtime environment.

Sender and recipient contexts retain derived AEAD keys, base nonces, and exporter secrets for the lifetime of the context. Exported secrets returned to the application also remain in memory as normal JavaScript objects.

#### User-Provided Algorithm Implementations

This library supports extensibility by allowing users to provide their own KEM, KDF, or AEAD implementations. The security of user-provided implementations is entirely the user's responsibility. This library validates only the shape of the factory return value and does not validate cryptographic correctness, domain separation, side-channel resistance, random number generation, key validation, output lengths, or AEAD nonce-safety of user-provided algorithm implementations.

### Threat Actors and Security Properties

This library aims to provide the security properties defined by the active HPKE drafts for Base and PSK modes. For a detailed analysis of threat models, security properties, and security considerations, refer to [Section 9 of draft-ietf-hpke-hpke-04](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-9).

### What is NOT Considered a Vulnerability

The following are explicitly **not** considered vulnerabilities in this library:

- **Prototype pollution** ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)): Attacks that exploit JavaScript prototype pollution are considered vulnerabilities in user application code or the runtime, not this library.
- **Object injection** ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)): Similar to prototype pollution, object injection attacks are outside the scope of this library.
- **Debugger/inspector access** ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)): If an attacker can attach a debugger to the process, they have already compromised the runtime environment.
- **Memory inspection**: Reading process memory, heap dumps, or core dumps to extract key material is a runtime-level attack.
- **Side-channel attacks** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)): Timing attacks, cache attacks, and other side-channel vulnerabilities in the underlying Web Cryptography implementations are not vulnerabilities in this library.
- **Compromised runtime environment**: Malicious or backdoored JavaScript runtimes, compromised system libraries, or tampered Web Cryptography implementations.
- **Supply chain attacks on the runtime** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): Compromised Node.js binaries, malicious browser builds, or similar supply chain attacks on the execution environment.
- **Supply chain attacks on third-party libraries** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): `hpke` has zero dependencies. `@panva/hpke-noble` depends on [@noble](https://paulmillr.com/noble/) cryptographic libraries. Supply chain compromises of third-party dependencies (including `@noble` libraries or any user-provided algorithm implementations) are not considered vulnerabilities in this project.
- **Denial of service via resource exhaustion** ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)): While the library validates inputs, it does not implement resource limits. Applications should implement their own rate limiting and resource management.
- **Application-level replay, downgrade, framing, key selection, or metadata exposure**: These properties are the responsibility of the protocol embedding this library.
- **Low-entropy or reused PSKs**: Passwords and other low-entropy secrets are not suitable PSKs. Reusing PSKs across unrelated protocols or security domains is application misuse.
- **Auth/AuthPSK modes**: These modes are not implemented because they are not part of the active standards-track HPKE draft targeted by this project.
- **Applications forwarding raw local errors**: Applications should not expose this library's diagnostic error classes, messages, stack traces, or distinguishable failure causes to attackers.
- **Issues in user-provided algorithm implementations**: Security flaws in custom KEM, KDF, or AEAD implementations provided by users are the user's responsibility.
