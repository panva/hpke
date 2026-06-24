import {
  LabeledDerive,
  LabeledExtract,
  LabeledExpand,
  concat,
  encode,
  I2OSP,
  ValidationError,
} from '../../index.ts'
import type * as HPKE from '../../index.ts'

import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { aessiv, gcm } from '@noble/ciphers/aes.js'
import { shake128, shake256 } from '@noble/hashes/sha3.js'
import { turboshake128, turboshake256 } from '@noble/hashes/sha3-addons.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_kem768_p256, ml_kem1024_p384, ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { type KEM as NobleKEM } from '@noble/post-quantum/utils.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { x448 } from '@noble/curves/ed448.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'

const AES_GCM_P_MAX = 2 ** 36 - 31
const CHACHA20_POLY1305_P_MAX = 2 ** 38 - 64

/**
 * AES-128-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 128-bit keys.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE AEAD Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.3)
 */
export const AEAD_AES_128_GCM: HPKE.AEADFactory = () =>
  createAead(0x0001, 'AES-128-GCM', 16, AES_GCM_P_MAX, gcm)

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 256-bit keys.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE AEAD Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.3)
 */
export const AEAD_AES_256_GCM: HPKE.AEADFactory = () =>
  createAead(0x0002, 'AES-256-GCM', 32, AES_GCM_P_MAX, gcm)

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses ChaCha20 stream cipher with Poly1305 MAC.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE AEAD Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.3)
 */
export const AEAD_ChaCha20Poly1305: HPKE.AEADFactory = () =>
  createAead(0x0003, 'ChaCha20Poly1305', 32, CHACHA20_POLY1305_P_MAX, chacha20poly1305)

/**
 * AES-256-SIV Deterministic Authenticated Encryption.
 *
 * Uses AES-SIV with a 256-bit double-wide key.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [DNHPKE DAE Identifiers](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.2)
 */
export const AEAD_AES_256_SIV: HPKE.AEADFactory = () => createAesSiv(0x8000, 'AES-256-SIV', 32)

/**
 * AES-512-SIV Deterministic Authenticated Encryption.
 *
 * Uses AES-SIV with a 512-bit double-wide key.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [DNHPKE DAE Identifiers](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.2)
 */
export const AEAD_AES_512_SIV: HPKE.AEADFactory = () => createAesSiv(0x8001, 'AES-512-SIV', 64)

function createAead(
  id: number,
  name: string,
  Nk: number,
  P_MAX: number,
  cipher: typeof chacha20poly1305 | typeof gcm,
): HPKE.AEAD {
  return {
    id,
    type: 'AEAD',
    name,
    Nk,
    Nn: 12,
    Nt: 16,
    async Seal(key, nonce, aad, pt) {
      if (pt.byteLength > P_MAX) {
        throw new RangeError('"pt" exceeds P_MAX')
      }
      return cipher(key, nonce, aad).encrypt(pt)
    },
    async Open(key, nonce, aad, ct) {
      return cipher(key, nonce, aad).decrypt(ct)
    },
  }
}

function createAesSiv(id: number, name: string, Nk: number): HPKE.AEAD {
  return {
    id,
    type: 'AEAD',
    name,
    Nk,
    Nn: 0,
    Nt: 16,
    async Seal(key, _nonce, aad, pt) {
      const sealed = aessiv(key, aad).encrypt(pt)
      return concat(slice(sealed, 16), slice(sealed, 0, 16))
    },
    async Open(key, _nonce, aad, ct) {
      if (ct.byteLength < 16) {
        throw new Error('Invalid ciphertext length')
      }
      const sealed = concat(slice(ct, ct.byteLength - 16), slice(ct, 0, ct.byteLength - 16))
      return aessiv(key, aad).decrypt(sealed)
    },
  }
}

/**
 * HKDF-SHA256 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-256 as the
 * hash function with an output length (Nh) of 32 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KDF Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.2)
 */
export const KDF_HKDF_SHA256: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0001, 'HKDF-SHA256', 32, sha256)

/**
 * HKDF-SHA384 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-384 as the
 * hash function with an output length (Nh) of 48 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KDF Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.2)
 */
export const KDF_HKDF_SHA384: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0002, 'HKDF-SHA384', 48, sha384)

/**
 * HKDF-SHA512 key derivation function.
 *
 * A two-stage KDF using HMAC-based Extract-and-Expand as specified in RFC 5869. Uses SHA-512 as the
 * hash function with an output length (Nh) of 64 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KDF Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.2)
 */
export const KDF_HKDF_SHA512: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0003, 'HKDF-SHA512', 64, sha512)

/**
 * SHAKE128 key derivation function.
 *
 * A one-stage KDF using the SHAKE128 extendable-output function (XOF) with an output length (Nh) of
 * 32 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-5)
 */
export const KDF_SHAKE128: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0010, 'SHAKE128', 32, shake128)

/**
 * SHAKE256 key derivation function.
 *
 * A one-stage KDF using the SHAKE256 extendable-output function (XOF) with an output length (Nh) of
 * 64 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-5)
 */
export const KDF_SHAKE256: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0011, 'SHAKE256', 64, shake256)

/**
 * TurboSHAKE128 key derivation function.
 *
 * A one-stage KDF using the TurboSHAKE128 extendable-output function (XOF) with an output length
 * (Nh) of 32 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-5)
 */
export const KDF_TurboSHAKE128: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0012, 'TurboSHAKE128', 32, turboshake128, 0x1f)

/**
 * TurboSHAKE256 key derivation function.
 *
 * A one-stage KDF using the TurboSHAKE256 extendable-output function (XOF) with an output length
 * (Nh) of 64 bytes.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ One-Stage KDFs](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-5)
 */
export const KDF_TurboSHAKE256: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0013, 'TurboSHAKE256', 64, turboshake256, 0x1f)

function createTwoStageKdf(
  id: number,
  name: string,
  Nh: number,
  hash: typeof sha256 | typeof sha384 | typeof sha512,
): HPKE.KDF {
  return {
    id,
    type: 'KDF',
    name,
    Nh,
    stages: 2,
    async Extract(salt, ikm) {
      return extract(hash, ikm, salt)
    },
    async Expand(prk, info, L) {
      return expand(hash, prk, info, L)
    },
    Derive: Unreachable,
  }
}

function createOneStageKdf(
  id: number,
  name: string,
  Nh: number,
  derive: typeof shake128 | typeof shake256 | typeof turboshake128 | typeof turboshake256,
  D?: number,
): HPKE.KDF {
  return {
    id,
    type: 'KDF',
    name,
    Nh,
    stages: 1,
    async Derive(labeled_ikm, L) {
      return derive(labeled_ikm, { dkLen: L, D })
    },
    Extract: Unreachable,
    Expand: Unreachable,
  }
}

const Unreachable = () => {
  throw new Error('unreachable')
}

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-256 curve and HKDF-SHA256.
 *
 * A Diffie-Hellman based KEM using the NIST P-256 elliptic curve (also known as secp256r1) with
 * HKDF-SHA256 for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.1)
 */
export const KEM_DHKEM_P256_HKDF_SHA256: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0010,
    name: 'DHKEM(P-256, HKDF-SHA256)',
    Nsecret: 32,
    Nenc: 65,
    Npk: 65,
    Nsk: 32,
    curve: p256,
    kdf: KDF_HKDF_SHA256,
    order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    bitmask: 0xff,
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using compact NIST P-256 representation and
 * HKDF-SHA256.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [DNHPKE Compact Representation](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.1)
 */
export const KEM_DHKEM_CP256_HKDF_SHA256: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0013,
    name: 'DHKEM(CP-256, HKDF-SHA256)',
    Nsecret: 32,
    Nenc: 32,
    Npk: 32,
    Nsk: 32,
    curve: p256,
    kdf: KDF_HKDF_SHA256,
    order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    bitmask: 0xff,
    compact: {
      prime: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
      b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    },
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-384 curve and HKDF-SHA384.
 *
 * A Diffie-Hellman based KEM using the NIST P-384 elliptic curve (also known as secp384r1) with
 * HKDF-SHA384 for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.1)
 */
export const KEM_DHKEM_P384_HKDF_SHA384: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0011,
    name: 'DHKEM(P-384, HKDF-SHA384)',
    Nsecret: 48,
    Nenc: 97,
    Npk: 97,
    Nsk: 48,
    curve: p384,
    kdf: KDF_HKDF_SHA384,
    order:
      0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    bitmask: 0xff,
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using compact NIST P-384 representation and
 * HKDF-SHA384.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [DNHPKE Compact Representation](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.1)
 */
export const KEM_DHKEM_CP384_HKDF_SHA384: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0014,
    name: 'DHKEM(CP-384, HKDF-SHA384)',
    Nsecret: 48,
    Nenc: 48,
    Npk: 48,
    Nsk: 48,
    curve: p384,
    kdf: KDF_HKDF_SHA384,
    order:
      0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    bitmask: 0xff,
    compact: {
      prime:
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
      b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
    },
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-521 curve and HKDF-SHA512.
 *
 * A Diffie-Hellman based KEM using the NIST P-521 elliptic curve (also known as secp521r1) with
 * HKDF-SHA512 for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.1)
 */
export const KEM_DHKEM_P521_HKDF_SHA512: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0012,
    name: 'DHKEM(P-521, HKDF-SHA512)',
    Nsecret: 64,
    Nenc: 133,
    Npk: 133,
    Nsk: 66,
    curve: p521,
    kdf: KDF_HKDF_SHA512,
    order:
      0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
    bitmask: 0x01,
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using compact NIST P-521 representation and
 * HKDF-SHA512.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [DNHPKE Compact Representation](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-dnhpke-08#section-4.1)
 */
export const KEM_DHKEM_CP521_HKDF_SHA512: HPKE.KEMFactory = () =>
  createDhKemNist({
    id: 0x0015,
    name: 'DHKEM(CP-521, HKDF-SHA512)',
    Nsecret: 64,
    Nenc: 66,
    Npk: 66,
    Nsk: 66,
    curve: p521,
    kdf: KDF_HKDF_SHA512,
    order:
      0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
    bitmask: 0x01,
    compact: {
      prime:
        0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
      b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
    },
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using Curve25519 and HKDF-SHA256.
 *
 * A Diffie-Hellman based KEM using the X25519 elliptic curve (Curve25519 for ECDH) with HKDF-SHA256
 * for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.1)
 */
export const KEM_DHKEM_X25519_HKDF_SHA256: HPKE.KEMFactory = () =>
  createDhKemX({
    id: 0x0020,
    name: 'DHKEM(X25519, HKDF-SHA256)',
    Nsecret: 32,
    Nenc: 32,
    Npk: 32,
    Nsk: 32,
    curve: x25519,
    kdf: KDF_HKDF_SHA256,
  })

/**
 * Diffie-Hellman Key Encapsulation Mechanism using Curve448 and HKDF-SHA512.
 *
 * A Diffie-Hellman based KEM using the X448 elliptic curve (Curve448 for ECDH) with HKDF-SHA512 for
 * key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03.html#section-7.1)
 */
export const KEM_DHKEM_X448_HKDF_SHA512: HPKE.KEMFactory = () =>
  createDhKemX({
    id: 0x0021,
    name: 'DHKEM(X448, HKDF-SHA512)',
    Nsecret: 64,
    Nenc: 56,
    Npk: 56,
    Nsk: 56,
    curve: x448,
    kdf: KDF_HKDF_SHA512,
  })

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-512).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-3)
 */
export const KEM_ML_KEM_512: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x0040,
    name: 'ML-KEM-512',
    Nsecret: 32,
    Nenc: 768,
    Npk: 800,
    Nsk: 64,
    kem: ml_kem512,
  })

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-768).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-3)
 */
export const KEM_ML_KEM_768: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x0041,
    name: 'ML-KEM-768',
    Nsecret: 32,
    Nenc: 1088,
    Npk: 1184,
    Nsk: 64,
    kem: ml_kem768,
  })

/**
 * Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM-1024).
 *
 * A post-quantum KEM based on structured lattices (FIPS 203 / CRYSTALS-Kyber).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-3)
 */
export const KEM_ML_KEM_1024: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x0042,
    name: 'ML-KEM-1024',
    Nsecret: 32,
    Nenc: 1568,
    Npk: 1568,
    Nsk: 64,
    kem: ml_kem1024,
  })

/**
 * Hybrid KEM combining ML-KEM-768 with X25519 (MLKEM768-X25519).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ Hybrid KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-4)
 */
export const KEM_MLKEM768_X25519: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x647a,
    name: 'MLKEM768-X25519',
    Nsecret: 32,
    Nenc: 1120,
    Npk: 1216,
    Nsk: 32,
    kem: ml_kem768_x25519,
  })

/**
 * Hybrid KEM combining ML-KEM-768 with P-256 (MLKEM768-P256).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ Hybrid KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-4)
 */
export const KEM_MLKEM768_P256: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x0050,
    name: 'MLKEM768-P256',
    Nsecret: 32,
    Nenc: 1153,
    Npk: 1249,
    Nsk: 32,
    kem: ml_kem768_p256,
  })

/**
 * Hybrid KEM combining ML-KEM-1024 with P-384 (MLKEM1024-P384).
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 *
 * @see [HPKE-PQ Hybrid KEM Identifiers](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04.html#section-4)
 */
export const KEM_MLKEM1024_P384: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x0051,
    name: 'MLKEM1024-P384',
    Nsecret: 32,
    Nenc: 1665,
    Npk: 1665,
    Nsk: 32,
    kem: ml_kem1024_p384,
  })

function createPqKem(config: {
  id: number
  name: string
  Nsecret: number
  Nenc: number
  Npk: number
  Nsk: number
  kem: NobleKEM
}): HPKE.KEM {
  const { id, name, Nsecret, Nenc, Npk, Nsk, kem: nobleKem } = config
  const suite_id = concat(encode('KEM'), I2OSP(id, 2))

  Object.freeze(NobleKey.prototype)
  const algorithm = { name }

  return {
    id,
    type: 'KEM',
    name,
    Nsecret,
    Nenc,
    Npk,
    Nsk,
    async DeriveKeyPair(ikm, extractable) {
      const seed = await LabeledDerive(
        {
          async Derive(ikm, L) {
            return shake256(ikm, { dkLen: L })
          },
        },
        suite_id,
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        Nsk,
      )
      const { secretKey, publicKey } = nobleKem.keygen(seed)

      return {
        privateKey: new NobleKey(priv, 'private', secretKey, extractable, algorithm, seed),
        publicKey: new NobleKey(priv, 'public', publicKey, true, algorithm),
      }
    },
    async GenerateKeyPair(extractable) {
      const ikm = crypto.getRandomValues(new Uint8Array(Nsk))
      return await this.DeriveKeyPair(ikm, extractable)
    },
    async SerializePublicKey(key) {
      NobleKey.validate(key, algorithm, true)
      return key.value(priv)
    },
    async DeserializePublicKey(key) {
      return new NobleKey(priv, 'public', slice(key), true, algorithm)
    },
    async SerializePrivateKey(key) {
      NobleKey.validate(key, algorithm, true)
      return (key as NobleKey).seed(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      const { secretKey } = nobleKem.keygen(key)
      return new NobleKey(priv, 'private', secretKey, extractable, algorithm, slice(key))
    },
    async Encap(pkR) {
      NobleKey.validate(pkR, algorithm)
      const { cipherText, sharedSecret } = nobleKem.encapsulate((pkR as NobleKey).value(priv))
      return { shared_secret: sharedSecret, enc: cipherText }
    },
    async Decap(enc, skR) {
      NobleKey.validate(skR, algorithm)
      return nobleKem.decapsulate(enc, (skR as NobleKey).value(priv))
    },
  }
}

async function deriveSharedSecret(
  kdf: HPKE.KDF,
  suite_id: Uint8Array,
  Nsecret: number,
  dh: Uint8Array,
  enc: Uint8Array,
  pkRm: Uint8Array,
): Promise<Uint8Array> {
  const kem_context = concat(enc, pkRm)
  const eae_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('eae_prk'), dh)
  return LabeledExpand(kdf, suite_id, eae_prk, encode('shared_secret'), kem_context, Nsecret)
}

function createDhKemNist(config: {
  id: number
  name: string
  Nsecret: number
  Nenc: number
  Npk: number
  Nsk: number
  curve: typeof p256 | typeof p384 | typeof p521
  kdf: HPKE.KDFFactory
  order: bigint
  bitmask: number
  compact?: { prime: bigint; b: bigint }
}): HPKE.KEM {
  const {
    id,
    name,
    Nsecret,
    Nenc,
    Npk,
    Nsk,
    curve,
    kdf: kdfFactory,
    order,
    bitmask,
    compact,
  } = config
  const kdf = kdfFactory()
  const suite_id = concat(encode('KEM'), I2OSP(id, 2))
  const algorithm = { name }

  async function deriveKeyPair(ikm: Uint8Array, extractable: boolean): Promise<HPKE.KeyPair> {
    const dkp_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('dkp_prk'), ikm)

    // Rejection sampling for NIST curves
    let sk = 0n
    let counter = 0
    let bytes: Uint8Array

    do {
      if (counter > 255) throw new Error('Key derivation failed')
      bytes = await LabeledExpand(
        kdf,
        suite_id,
        dkp_prk,
        encode('candidate'),
        Uint8Array.of(counter),
        Nsk,
      )
      bytes[0]! &= bitmask
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      sk = 0n
      // NOTE: The `else` branch hard-codes `getUint16` and is only correct when
      // the trailing tail is exactly 2 bytes. This is fine for the curves wired
      // up here (Nsk ∈ {32, 48, 66} → tail ∈ {0, 2}). Adding any curve with
      // Nsk % 8 ∉ {0, 2} would silently produce wrong scalars — switch to a
      // byte-wise accumulator (see OS2IP in ../../index.ts) before doing so.
      for (let i = 0; i < Nsk; i += 8) {
        const remaining = Nsk - i
        if (remaining >= 8) {
          sk = (sk << 64n) | view.getBigUint64(i, false)
        } else {
          sk = (sk << BigInt(remaining * 8)) | BigInt(view.getUint16(i, false))
        }
      }
      counter++
    } while (sk === 0n || sk >= order)

    const secretKey = bytes!
    const publicKey = curve.getPublicKey(secretKey, false)

    curve.Point.fromBytes(publicKey).assertValidity()

    return {
      privateKey: new NobleKey(priv, 'private', secretKey, extractable, { name }),
      publicKey: new NobleKey(priv, 'public', publicKey, true, { name }),
    }
  }

  function serializePublicKeyBytes(key: Uint8Array) {
    return compact ? slice(key, 1, 1 + Nsk) : key
  }

  Object.freeze(NobleKey.prototype)
  return {
    id,
    type: 'KEM',
    name,
    Nsecret,
    Nenc,
    Npk,
    Nsk,
    async DeriveKeyPair(ikm, extractable) {
      return await deriveKeyPair(ikm, extractable)
    },
    async GenerateKeyPair(extractable) {
      const ikm = crypto.getRandomValues(new Uint8Array(Nsk))
      return await this.DeriveKeyPair(ikm, extractable)
    },
    async SerializePublicKey(key) {
      NobleKey.validate(key, algorithm, true)
      return serializePublicKeyBytes(key.value(priv))
    },
    async DeserializePublicKey(key) {
      const publicKey = compact ? recoverPublicKeyNist(compact, Nsk, key) : key
      curve.Point.fromBytes(publicKey).assertValidity()
      return new NobleKey(priv, 'public', slice(publicKey), true, algorithm)
    },
    async SerializePrivateKey(key) {
      NobleKey.validate(key, algorithm, true)
      return (key as NobleKey).value(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      const privateKey = compact ? normalizePrivateKeyNist(key, order, Nsk) : slice(key)
      return new NobleKey(priv, 'private', privateKey, extractable, algorithm)
    },
    async Encap(pkR) {
      NobleKey.validate(pkR, algorithm)

      const pkRValue = (pkR as NobleKey).value(priv)
      curve.Point.fromBytes(pkRValue).assertValidity()

      const ekp = await this.GenerateKeyPair(false)
      const skE = (ekp.privateKey as NobleKey).value(priv)
      const enc = await this.SerializePublicKey(ekp.publicKey)
      const pkRm = await this.SerializePublicKey(pkR)

      const dh = slice(curve.getSharedSecret(skE, pkRValue), 1)
      checkNotAllZeros(dh)

      return { shared_secret: await deriveSharedSecret(kdf, suite_id, Nsecret, dh, enc, pkRm), enc }
    },
    async Decap(enc, skR, pkR) {
      NobleKey.validate(skR, algorithm)

      const skRValue = (skR as NobleKey).value(priv)
      pkR ??= new NobleKey(priv, 'public', curve.getPublicKey(skRValue, false), true, algorithm)
      NobleKey.validate(pkR, algorithm)

      const pkE = (await this.DeserializePublicKey(enc)) as NobleKey
      const pkEValue = pkE.value(priv)
      const dh = slice(curve.getSharedSecret(skRValue, pkEValue), 1)
      checkNotAllZeros(dh)
      const pkRm = await this.SerializePublicKey(pkR)

      return await deriveSharedSecret(kdf, suite_id, Nsecret, dh, enc, pkRm)
    },
  }
}

function mod(a: bigint, p: bigint): bigint {
  const r = a % p
  return r < 0n ? r + p : r
}

function modPow(base: bigint, exponent: bigint, prime: bigint): bigint {
  let result = 1n
  base = mod(base, prime)
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = mod(result * base, prime)
    }
    base = mod(base * base, prime)
    exponent >>= 1n
  }
  return result
}

function os2ip(x: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < x.byteLength; i++) {
    result = result * 256n + BigInt(x[i]!)
  }
  return result
}

function i2osp(value: bigint, byteLength: number): Uint8Array {
  const result = new Uint8Array(byteLength)
  let n = value

  for (let i = byteLength - 1; i >= 0; i--) {
    result[i] = Number(n & 0xffn)
    n >>= 8n
  }

  return result
}

function normalizePrivateKeyNist(key: Uint8Array, order: bigint, Nsk: number): Uint8Array {
  const d = os2ip(key) % order
  if (d === 0n) {
    throw new Error('Invalid scalar')
  }
  return i2osp(d, Nsk)
}

function recoverPublicKeyNist(
  { prime, b }: { prime: bigint; b: bigint },
  coordinateSize: number,
  key: Uint8Array,
) {
  const x = os2ip(key)
  if (x >= prime) {
    throw new Error('Invalid public key')
  }

  const rhs = mod(x * x * x + (prime - 3n) * x + b, prime)
  const y = modPow(rhs, (prime + 1n) >> 2n, prime)
  if (mod(y * y, prime) !== rhs) {
    throw new Error('Invalid public key')
  }

  return concat(Uint8Array.of(0x04), key, i2osp(y, coordinateSize))
}

function createDhKemX(config: {
  id: number
  name: string
  Nsecret: number
  Nenc: number
  Npk: number
  Nsk: number
  curve: typeof x25519 | typeof x448
  kdf: HPKE.KDFFactory
}): HPKE.KEM {
  const { id, name, Nsecret, Nenc, Npk, Nsk, curve, kdf: kdfFactory } = config
  const kdf = kdfFactory()
  const suite_id = concat(encode('KEM'), I2OSP(id, 2))
  const algorithm = { name }

  Object.freeze(NobleKey.prototype)
  return {
    id,
    type: 'KEM',
    name,
    Nsecret,
    Nenc,
    Npk,
    Nsk,
    async DeriveKeyPair(ikm, extractable) {
      const dkp_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('dkp_prk'), ikm)
      const sk = await LabeledExpand(kdf, suite_id, dkp_prk, encode('sk'), new Uint8Array(), Nsk)
      const pk = curve.getPublicKey(sk)

      return {
        privateKey: new NobleKey(priv, 'private', sk, extractable, algorithm),
        publicKey: new NobleKey(priv, 'public', pk, true, algorithm),
      }
    },
    async GenerateKeyPair(extractable) {
      const ikm = crypto.getRandomValues(new Uint8Array(Nsk))
      return await this.DeriveKeyPair(ikm, extractable)
    },
    async SerializePublicKey(key) {
      NobleKey.validate(key, algorithm, true)
      return key.value(priv)
    },
    async DeserializePublicKey(key) {
      return new NobleKey(priv, 'public', slice(key), true, algorithm)
    },
    async SerializePrivateKey(key) {
      NobleKey.validate(key, algorithm, true)
      return (key as NobleKey).value(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      return new NobleKey(priv, 'private', slice(key), extractable, algorithm)
    },
    async Encap(pkR) {
      NobleKey.validate(pkR, algorithm)

      const ekp = await this.GenerateKeyPair(false)
      const enc = (ekp.publicKey as NobleKey).value(priv)
      const dh = curve.getSharedSecret(
        (ekp.privateKey as NobleKey).value(priv),
        (pkR as NobleKey).value(priv),
      )
      checkNotAllZeros(dh)

      return {
        shared_secret: await deriveSharedSecret(
          kdf,
          suite_id,
          Nsecret,
          dh,
          enc,
          (pkR as NobleKey).value(priv),
        ),
        enc,
      }
    },
    async Decap(enc, skR, pkR) {
      NobleKey.validate(skR, algorithm)

      const skRValue = (skR as NobleKey).value(priv)
      pkR ??= (await this.DeserializePublicKey(curve.getPublicKey(skRValue))) as NobleKey
      NobleKey.validate(pkR, algorithm)

      const pkE = (await this.DeserializePublicKey(enc)) as NobleKey
      const dh = curve.getSharedSecret(skRValue, pkE.value(priv))
      checkNotAllZeros(dh)

      return await deriveSharedSecret(
        kdf,
        suite_id,
        Nsecret,
        dh,
        enc,
        (pkR as NobleKey).value(priv),
      )
    },
  }
}

const InvalidInvocation = (_: typeof priv) => {
  if (_ !== priv) {
    throw new Error('invalid invocation')
  }
}
const priv = Symbol()
class NobleKey implements HPKE.Key {
  #type: 'public' | 'private'
  #extractable: boolean
  #algorithm: KeyAlgorithm
  #value: Uint8Array
  #seed?: Uint8Array | undefined

  static #isValid(key: NobleKey): boolean {
    return key.#algorithm !== undefined
  }

  static validate(
    key: unknown,
    algorithm: KeyAlgorithm,
    extractable?: boolean,
  ): asserts key is NobleKey {
    if ((key as NobleKey).algorithm?.name !== algorithm.name) {
      throw new TypeError(`key algorithm must be ${algorithm.name}`)
    }
    try {
      if (!NobleKey.#isValid(key as NobleKey)) {
        throw new TypeError('unexpected key constructor')
      }
    } catch {
      throw new TypeError('unexpected key constructor')
    }
    if (extractable && !(key as NobleKey).extractable) {
      throw new TypeError('key must be extractable')
    }
  }

  constructor(
    _: typeof priv,
    type: 'public' | 'private',
    value: Uint8Array,
    extractable: boolean,
    algorithm: KeyAlgorithm,
    seed?: Uint8Array,
  ) {
    InvalidInvocation(_)
    this.#type = type
    this.#value = value
    this.#extractable = extractable
    this.#algorithm = algorithm
    this.#seed = seed
  }

  get algorithm() {
    return { name: this.#algorithm.name }
  }

  get extractable() {
    return this.#extractable
  }

  get type() {
    return this.#type
  }

  value(_: typeof priv) {
    InvalidInvocation(_)
    return slice(this.#value)
  }

  seed(_: typeof priv) {
    InvalidInvocation(_)
    return slice(this.#seed!)
  }
}

function checkNotAllZeros(buffer: Uint8Array): void {
  let or = 0
  for (let i = 0; i < buffer.length; i++) {
    or |= buffer[i]!
  }
  if (or === 0) {
    throw new ValidationError('DH shared secret is an all-zero value')
  }
}

function slice(buffer: Uint8Array, start?: number, end?: number) {
  return Uint8Array.prototype.slice.call(buffer, start, end)
}
