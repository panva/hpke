# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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
