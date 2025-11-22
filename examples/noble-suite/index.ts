import { LabeledDerive, LabeledExtract, LabeledExpand, concat, encode, I2OSP } from '../../index.ts'
import type * as HPKE from '../../index.ts'

import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { gcm } from '@noble/ciphers/aes.js'
import { shake128, shake256 } from '@noble/hashes/sha3.js'
import { turboshake128, turboshake256 } from '@noble/hashes/sha3-addons.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { XWing } from '@noble/post-quantum/hybrid.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { x448 } from '@noble/curves/ed448.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'

/**
 * AES-128-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 128-bit keys.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 */
export const AEAD_AES_128_GCM: HPKE.AEADFactory = () => createAead(0x0001, 'AES-128-GCM', 16, gcm)

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses AES in Galois/Counter Mode with 256-bit keys.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 */
export const AEAD_AES_256_GCM: HPKE.AEADFactory = () => createAead(0x0002, 'AES-256-GCM', 32, gcm)

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
 *
 * Uses ChaCha20 stream cipher with Poly1305 MAC.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 */
export const AEAD_ChaCha20Poly1305: HPKE.AEADFactory = () =>
  createAead(0x0003, 'ChaCha20Poly1305', 32, chacha20poly1305)

function createAead(
  id: number,
  name: string,
  Nk: number,
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
      return cipher(key, nonce, aad).encrypt(pt)
    },
    async Open(key, nonce, aad, ct) {
      return cipher(key, nonce, aad).decrypt(ct)
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
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-384 curve and HKDF-SHA384.
 *
 * A Diffie-Hellman based KEM using the NIST P-384 elliptic curve (also known as secp384r1) with
 * HKDF-SHA384 for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
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
 * Diffie-Hellman Key Encapsulation Mechanism using NIST P-521 curve and HKDF-SHA512.
 *
 * A Diffie-Hellman based KEM using the NIST P-521 elliptic curve (also known as secp521r1) with
 * HKDF-SHA512 for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
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
 * Diffie-Hellman Key Encapsulation Mechanism using Curve25519 and HKDF-SHA256.
 *
 * A Diffie-Hellman based KEM using the X25519 elliptic curve (Curve25519 for ECDH) with HKDF-SHA256
 * for key derivation.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
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
 * Hybrid post-quantum Key Encapsulation Mechanism combining ML-KEM-768 and X25519.
 *
 * A hybrid KEM that combines the post-quantum ML-KEM-768 with the classical X25519 ECDH to provide
 * both post-quantum security and backwards compatibility.
 *
 * This is a factory function that must be passed to the {@link HPKE.CipherSuite} constructor.
 */
export const KEM_MLKEM768_X25519: HPKE.KEMFactory = () =>
  createPqKem({
    id: 0x647a,
    name: 'MLKEM768-X25519',
    Nsecret: 32,
    Nenc: 1120,
    Npk: 1216,
    Nsk: 32,
    kem: XWing,
  })

function createPqKem(config: {
  id: number
  name: string
  Nsecret: number
  Nenc: number
  Npk: number
  Nsk: number
  kem: typeof ml_kem512 | typeof ml_kem768 | typeof ml_kem1024 | typeof XWing
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
      assertNobleKey(key, algorithm)
      return key.value(priv)
    },
    async DeserializePublicKey(key) {
      return new NobleKey(priv, 'public', key.slice(), true, algorithm)
    },
    async SerializePrivateKey(key) {
      assertNobleKey(key, algorithm)
      return (key as NobleKey).seed(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      const { secretKey } = nobleKem.keygen(key)
      return new NobleKey(priv, 'private', secretKey, extractable, algorithm, key.slice())
    },
    async Encap(pkR) {
      assertNobleKey(pkR, algorithm)
      const { cipherText, sharedSecret } = nobleKem.encapsulate((pkR as NobleKey).value(priv))
      return { shared_secret: sharedSecret, enc: cipherText }
    },
    async Decap(enc, skR) {
      assertNobleKey(skR, algorithm)
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
}): HPKE.KEM {
  const { id, name, Nsecret, Nenc, Npk, Nsk, curve, kdf: kdfFactory, order, bitmask } = config
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
      assertNobleKey(key, algorithm)
      return key.value(priv)
    },
    async DeserializePublicKey(key) {
      curve.Point.fromBytes(key).assertValidity()
      return new NobleKey(priv, 'public', key.slice(), true, algorithm)
    },
    async SerializePrivateKey(key) {
      assertNobleKey(key, algorithm)
      return (key as NobleKey).value(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      return new NobleKey(priv, 'private', key.slice(), extractable, algorithm)
    },
    async Encap(pkR) {
      assertNobleKey(pkR, algorithm)

      const pkRValue = (pkR as NobleKey).value(priv)
      curve.Point.fromBytes(pkRValue).assertValidity()

      const ekp = await this.GenerateKeyPair(false)
      const skE = (ekp.privateKey as NobleKey).value(priv)
      const enc = (ekp.publicKey as NobleKey).value(priv)

      const dh = curve.getSharedSecret(skE, pkRValue).slice(1)
      checkNotAllZeros(dh)

      return {
        shared_secret: await deriveSharedSecret(kdf, suite_id, Nsecret, dh, enc, pkRValue),
        enc,
      }
    },
    async Decap(enc, skR, pkR) {
      assertNobleKey(skR, algorithm)

      const skRValue = (skR as NobleKey).value(priv)
      pkR ??= (await this.DeserializePublicKey(curve.getPublicKey(skRValue, false))) as NobleKey
      assertNobleKey(pkR, algorithm)

      const pkE = (await this.DeserializePublicKey(enc)) as NobleKey
      const pkEValue = pkE.value(priv)
      const dh = curve.getSharedSecret(skRValue, pkEValue).slice(1)
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
      assertNobleKey(key, algorithm)
      return key.value(priv)
    },
    async DeserializePublicKey(key) {
      return new NobleKey(priv, 'public', key.slice(), true, algorithm)
    },
    async SerializePrivateKey(key) {
      assertNobleKey(key, algorithm)
      return (key as NobleKey).value(priv)
    },
    async DeserializePrivateKey(key, extractable) {
      return new NobleKey(priv, 'private', key.slice(), extractable, algorithm)
    },
    async Encap(pkR) {
      assertNobleKey(pkR, algorithm)

      const ekp = await this.GenerateKeyPair(false)
      const enc = (ekp.publicKey as NobleKey).value(priv)
      const dh = curve.getSharedSecret(
        (ekp.privateKey as NobleKey).value(priv),
        (pkR as NobleKey).value(priv),
      )

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
      assertNobleKey(skR, algorithm)

      const skRValue = (skR as NobleKey).value(priv)
      pkR ??= (await this.DeserializePublicKey(curve.getPublicKey(skRValue))) as NobleKey
      assertNobleKey(pkR, algorithm)

      const pkE = (await this.DeserializePublicKey(enc)) as NobleKey
      const dh = curve.getSharedSecret(skRValue, pkE.value(priv))

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

function assertNobleKey(key: HPKE.Key, algorithm: KeyAlgorithm): asserts key is NobleKey {
  if (key.algorithm.name !== algorithm.name) {
    throw new TypeError(`key algorithm must be ${algorithm.name}`)
  }
  if (!(key instanceof NobleKey) || Object.getPrototypeOf(key) !== NobleKey.prototype) {
    throw new TypeError('unexpected key constructor')
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

  constructor(
    _: typeof priv,
    type: 'public' | 'private',
    value: Uint8Array,
    extractable: boolean,
    algorithm: KeyAlgorithm,
    seed?: Uint8Array,
  ) {
    InvalidInvocation(priv)
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
    InvalidInvocation(priv)
    return this.#value.slice()
  }

  seed(_: typeof priv) {
    InvalidInvocation(priv)
    return this.#seed!.slice()
  }
}

function checkNotAllZeros(buffer: Uint8Array): void {
  let allZeros = 1
  for (let i = 0; i < buffer.length; i++) {
    allZeros &= buffer[i]! === 0 ? 1 : 0
  }
  if (allZeros === 1) {
    throw new Error('DH shared secret is an all-zero value')
  }
}
