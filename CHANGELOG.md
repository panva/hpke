# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [1.1.6](https://github.com/panva/hpke/compare/v1.1.5...v1.1.6) (2026-09-04)

### Documentation

* align hybrid KEM SHAKE256 requirements ([d102eb6](https://github.com/panva/hpke/commit/d102eb620345deff7446de0fd5979ef98bb9122e))

### Refactor

* delegate EC public key recovery to Web Crypto ([5df54f5](https://github.com/panva/hpke/commit/5df54f58a545231878274622e24f1e0b8e899dd8))

## [1.1.5](https://github.com/panva/hpke/compare/v1.1.4...v1.1.5) (2026-09-03)

### Refactor

* detect and wire PQ/T Hybrids through the Hybrid KEM algorithms ([b8f7c2a](https://github.com/panva/hpke/commit/b8f7c2a2009a9ee36640aed2b955254b2038b090))

## [1.1.4](https://github.com/panva/hpke/compare/v1.1.3...v1.1.4) (2026-08-11)

### Documentation

* render API indexes as tables ([8c4c53e](https://github.com/panva/hpke/commit/8c4c53eae3e795ff115ca2f3ee7921799c9737b9))
* update references ([3d4ba10](https://github.com/panva/hpke/commit/3d4ba1022751bc9309c7c75e91e47d788073c145))

### Refactor

* **types:** preserve concrete KEM key types ([218318f](https://github.com/panva/hpke/commit/218318f314d57a08056b9f8bc51d2f7c198d1c13))

## [1.1.3](https://github.com/panva/hpke/compare/v1.1.2...v1.1.3) (2026-06-25)


### Refactor

* **aead:** enforce plaintext size limits ([e9ebab5](https://github.com/panva/hpke/commit/e9ebab5283164482ec3e1cbe3bda65a9e1345601))
* **context:** bound sequence counter by nonce size ([7d577c0](https://github.com/panva/hpke/commit/7d577c0ce8a157fbadff5c750638248575a4df04))
* **dhkem:** centralize KDF stage handling ([26c50b0](https://github.com/panva/hpke/commit/26c50b0ca22a90dfc13ca1041179587d0784eda9))

## [1.1.2](https://github.com/panva/hpke/compare/v1.1.1...v1.1.2) (2026-06-11)


### Refactor

* avoid copying/slicing buffersource inputs before subtle() ([afc7ad3](https://github.com/panva/hpke/commit/afc7ad39f3a5ee0d33983727b4d73ef33f8f5d8c)), closes [#38](https://github.com/panva/hpke/issues/38)
* avoid HKDF empty-salt HMAC key re-import ([e560e1e](https://github.com/panva/hpke/commit/e560e1e7f44c8cd3207ea3aceb8d277e2f5bedbc))
* avoid HKDF PRK re-import on subsequent Expand calls ([d67626d](https://github.com/panva/hpke/commit/d67626d89b3f4a68cf29b7e186a30c8fa6f2295b))
* generate non-extractable ephemeral keys in hybrid KEM encapsulation ([ef79333](https://github.com/panva/hpke/commit/ef793337cd9b99054a66dffee6362419dfadc2cc))
* validate two-stage KDF Export length limit of 255*Nh upfront ([08ddc98](https://github.com/panva/hpke/commit/08ddc9866d6a811aab9db42a94a237e01d5c0a00))

## [1.1.1](https://github.com/panva/hpke/compare/v1.1.0...v1.1.1) (2026-05-15)


### Documentation

* add a caution block to the ML-KEM-512 export ([bde2f68](https://github.com/panva/hpke/commit/bde2f68f23940cb322b37c45175cffc2d94483f5))
* update examples ([cd67c2f](https://github.com/panva/hpke/commit/cd67c2ff2158b4705f6cefa71cfef1d5b0f77ceb))


### Refactor

* avoid AEAD key re-import on subsequent Context<Role>.Open/Seal ([c36c54c](https://github.com/panva/hpke/commit/c36c54c082597e8ab4794635537353e35394b716))
* cache ASCII label encodings at module scope ([20eedf2](https://github.com/panva/hpke/commit/20eedf2142f4ea92d466ca0f3671298247f81bc2))
* inline ComputeNonce and drop xor helper ([772ca09](https://github.com/panva/hpke/commit/772ca093538163cf4f35c821a76332b307f3b932))
* NIST curve DeserializePrivateKey and DeriveKeyPair optimizations ([11b6c55](https://github.com/panva/hpke/commit/11b6c557affd9fef75ead15005daf49e1574e673))

## [1.1.0](https://github.com/panva/hpke/compare/v1.0.6...v1.1.0) (2026-03-31)


### Features

* add Web Cryptography-based TurboSHAKE KDF exports ([a29413b](https://github.com/panva/hpke/commit/a29413b7969cd7ccf65ca23e21c5e23a7545abce))

## [1.0.6](https://github.com/panva/hpke/compare/v1.0.5...v1.0.6) (2026-03-04)


### Fixes

* build script munching unintended symbols ([b76a031](https://github.com/panva/hpke/commit/b76a031f215ca31b2a85ff2cc7bfbcbce1032436))

## [1.0.5](https://github.com/panva/hpke/compare/v1.0.4...v1.0.5) (2026-03-04)


### Refactor

* align internal naming with HPKE spec conventions ([a926ca1](https://github.com/panva/hpke/commit/a926ca13c5f941f287a09976aa8edce71ecf3a67))


### Documentation

* add links to IETF spec sections ([0bcfdb3](https://github.com/panva/hpke/commit/0bcfdb37a4b0d041445a7c691e3a5a0c89e2aec3))

## [1.0.4](https://github.com/panva/hpke/compare/v1.0.3...v1.0.4) (2026-02-16)


### Refactor

* account for an upcoming Web Cryptography change ([8503c7d](https://github.com/panva/hpke/commit/8503c7d4dc5ae09c156a09062002f7d78f8f675b))

## [1.0.3](https://github.com/panva/hpke/compare/v1.0.2...v1.0.3) (2025-12-21)


### Fixes

* align main and noble release versions and deps ([82d8d2b](https://github.com/panva/hpke/commit/82d8d2bf1f94455d31a405454dbe2caf71f4b08e))

## [1.0.2](https://github.com/panva/hpke/compare/v1.0.1...v1.0.2) (2025-12-21)


### Refactor

* **@panva/hpke-noble:** use [@noble](https://github.com/noble) hybrid KEMs ([0223abc](https://github.com/panva/hpke/commit/0223abc1c9afd1abd3e0adec5fab26b968f27d09))

## [1.0.1](https://github.com/panva/hpke/compare/v1.0.0...v1.0.1) (2025-12-05)


### Documentation

* variety of JSDoc updates ([b2cbf82](https://github.com/panva/hpke/commit/b2cbf8263717c5efeb72d55c333b3190275abe46))

## [1.0.0](https://github.com/panva/hpke/compare/v0.4.4...v1.0.0) (2025-12-02)


### Refactor

* rename package, it is now just "hpke" ([2996ad8](https://github.com/panva/hpke/commit/2996ad846dba0d18da3c1c26966218da73667038))

## [0.4.4](https://github.com/panva/hpke/compare/v0.4.3...v0.4.4) (2025-12-02)


### Refactor

* add additional assertValidity checks to the noble implementations ([e46795a](https://github.com/panva/hpke/commit/e46795a241aff80e90f26dcd1abefbfe74ad1f3e))
* perform the same operation regardless of byte values in checkNotAllZeros ([15f79d5](https://github.com/panva/hpke/commit/15f79d5ea8856183449a6ac2d5c478b4f5fa0d20))

## [0.4.3](https://github.com/panva/hpke/compare/v0.4.2...v0.4.3) (2025-11-30)


### Fixes

* don't fall for Node's Buffer.prototype.slice ([fa4c166](https://github.com/panva/hpke/commit/fa4c166fa32ba713832b553d985aef9889721d6c))

## [0.4.2](https://github.com/panva/hpke/compare/v0.4.1...v0.4.2) (2025-11-30)


### Fixes

* correct I2OSP for numbers larger than 32 bits ([5b632c6](https://github.com/panva/hpke/commit/5b632c6f34955e41fdcb7477be22ff7c88dd03b5))
* use psk byteLength for mode determination ([ad34537](https://github.com/panva/hpke/commit/ad34537930e385979fa06ab26889d1f921c3ef2e))


### Refactor

* handle edge cases in pointAdd ([1a63302](https://github.com/panva/hpke/commit/1a63302fbbdc1e35097725f194d6c86cb0b4a96b))

## [0.4.1](https://github.com/panva/hpke/compare/v0.4.0...v0.4.1) (2025-11-29)


### Refactor

* more custom key non-extractable checks ([3d02b02](https://github.com/panva/hpke/commit/3d02b02b96ba767de3f042c10cdd36019b43b690))

## [0.4.0](https://github.com/panva/hpke/compare/v0.3.0...v0.4.0) (2025-11-27)


### ⚠ BREAKING CHANGES

* encapsulatedKey is now encapsulatedSecret

### Refactor

* encapsulatedKey is now encapsulatedSecret ([3a10dac](https://github.com/panva/hpke/commit/3a10dacd82ee96f9c24d401e911a5bca0979c5ea))

## [0.3.0](https://github.com/panva/hpke/compare/v0.2.7...v0.3.0) (2025-11-25)


### ⚠ BREAKING CHANGES

* Single-Shot APIs aad is moved to the options argument

### Refactor

* Single-Shot APIs aad is moved to the options argument ([962b0ea](https://github.com/panva/hpke/commit/962b0ea37e44b88a6487e1413fc20c01a896c494))

## [0.2.7](https://github.com/panva/hpke/compare/v0.2.6...v0.2.7) (2025-11-24)


### Features

* add the remaining hybrids to extensibility ([6472e8e](https://github.com/panva/hpke/commit/6472e8e01aff94684b44b14e923cb4c2ba161573))

## [0.2.6](https://github.com/panva/hpke/compare/v0.2.5...v0.2.6) (2025-11-22)


### Fixes

* ensure custom non-extractable Key instances cannot be extracted through a KEM instance ([1a74f06](https://github.com/panva/hpke/commit/1a74f063996dfb4604f8b7ae69a51c1d505f8986))

## [0.2.5](https://github.com/panva/hpke/compare/v0.2.4...v0.2.5) (2025-11-22)


### Refactor

* capture stacktraces when Error.captureStackTrace is available ([4b76796](https://github.com/panva/hpke/commit/4b76796ffe4cad8c527abad81ae606b75434a2fb))


### Documentation

* add JSDoc for exported utilities ([fa3d6bf](https://github.com/panva/hpke/commit/fa3d6bfffa593bbfd9042e66574ecf1197897a48))

## [0.2.4](https://github.com/panva/hpke/compare/v0.2.3...v0.2.4) (2025-11-21)


### Fixes

* set P-256 group Nseed constant correctly ([0417448](https://github.com/panva/hpke/commit/0417448364c23fb1a59a9984f42de40f06264a6e))

## [0.2.3](https://github.com/panva/hpke/compare/v0.2.2...v0.2.3) (2025-11-19)


### Refactor

* apply workarounds for pkcs8 imports to hybrids ([9a07460](https://github.com/panva/hpke/commit/9a0746078e0433f42a7927840cfe7761aa46dbe7))

## [0.2.2](https://github.com/panva/hpke/compare/v0.2.1...v0.2.2) (2025-11-17)


### Fixes

* work around firefox and safari NIST curve pkcs8 format limitations ([df28631](https://github.com/panva/hpke/commit/df2863108a4939f221a52ca930efd75b8da4aa4b))

## [0.2.1](https://github.com/panva/hpke/compare/v0.2.0...v0.2.1) (2025-11-17)


### Fixes

* correctly detext SharedArrayBuffer ([b33ea4c](https://github.com/panva/hpke/commit/b33ea4c5bbe5f8240d0a4ef7b629b6ec80561231))

## [0.2.0](https://github.com/panva/hpke/compare/v0.1.0...v0.2.0) (2025-11-17)


### ⚠ BREAKING CHANGES

* options.psk_id is now options.pskId
* encapsulated_key is now encapsulatedKey

### Refactor

* the snakeCase apocalypse ([5b2e675](https://github.com/panva/hpke/commit/5b2e67539fcdb2af08a8fc04e240e181e380ed7a))

## 0.1.0 (2025-11-17)


### Features

* Implementation of RFC9180, draft-ietf-hpke-hpke-02, and draft-ietf-hpke-pq-03 ([09a81d9](https://github.com/panva/hpke/commit/09a81d90141264a2818470b995727e7a15bb6ea8))

## 0.0.0 (2025-11-17)

npm placeholder
