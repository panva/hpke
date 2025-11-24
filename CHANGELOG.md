# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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
