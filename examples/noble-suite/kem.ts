import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { XWing, ecdhKem } from '@noble/post-quantum/hybrid.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { x448 } from '@noble/curves/ed448.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import { shake256 } from '@noble/hashes/sha3.js'
import type * as HPKE from '../../index.ts'
import { LabeledDerive, LabeledExtract, LabeledExpand, concat, encode, I2OSP } from '../../index.ts'
import { KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512 } from './kdf.ts'

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

export const KEM_DHKEM_X25519_HKDF_SHA256: HPKE.KEMFactory = () =>
  createDhKemX({
    id: 0x0020,
    name: 'DHKEM(X25519, HKDF-SHA256)',
    Nsecret: 32,
    Nenc: 32,
    Npk: 32,
    Nsk: 32,
    kem: ecdhKem(x25519),
    kdf: KDF_HKDF_SHA256,
  })

export const KEM_DHKEM_X448_HKDF_SHA512: HPKE.KEMFactory = () =>
  createDhKemX({
    id: 0x0021,
    name: 'DHKEM(X448, HKDF-SHA512)',
    Nsecret: 64,
    Nenc: 56,
    Npk: 56,
    Nsk: 56,
    kem: ecdhKem(x448),
    kdf: KDF_HKDF_SHA512,
  })

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
      return this.DeriveKeyPair(ikm, extractable)
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

  async function deriveSharedSecret(
    dh: Uint8Array,
    enc: Uint8Array,
    pkRm: Uint8Array,
  ): Promise<Uint8Array> {
    const kem_context = concat(enc, pkRm)
    const eae_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('eae_prk'), dh)
    return LabeledExpand(kdf, suite_id, eae_prk, encode('shared_secret'), kem_context, Nsecret)
  }

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
      sk = bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n)
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
      return deriveKeyPair(ikm, extractable)
    },
    async GenerateKeyPair(extractable) {
      const ikm = crypto.getRandomValues(new Uint8Array(Nsk))
      return this.DeriveKeyPair(ikm, extractable)
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
        shared_secret: await deriveSharedSecret(dh, enc, pkRValue),
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

      return deriveSharedSecret(dh, enc, (pkR as NobleKey).value(priv))
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
  kem: NobleKEM
  kdf: HPKE.KDFFactory
}): HPKE.KEM {
  const { id, name, Nsecret, Nenc, Npk, Nsk, kem: nobleKem, kdf: kdfFactory } = config
  const kdf = kdfFactory()
  const suite_id = concat(encode('KEM'), I2OSP(id, 2))
  const algorithm = { name }

  async function deriveSharedSecret(
    dh: Uint8Array,
    enc: Uint8Array,
    pkRm: Uint8Array,
  ): Promise<Uint8Array> {
    const kem_context = concat(enc, pkRm)
    const eae_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('eae_prk'), dh)
    return LabeledExpand(kdf, suite_id, eae_prk, encode('shared_secret'), kem_context, Nsecret)
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
      const dkp_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('dkp_prk'), ikm)
      const sk = await LabeledExpand(kdf, suite_id, dkp_prk, encode('sk'), new Uint8Array(), Nsk)
      const { secretKey, publicKey } = nobleKem.keygen(sk)

      return {
        privateKey: new NobleKey(priv, 'private', secretKey, extractable, algorithm),
        publicKey: new NobleKey(priv, 'public', publicKey, true, algorithm),
      }
    },
    async GenerateKeyPair(extractable) {
      const ikm = crypto.getRandomValues(new Uint8Array(Nsk))
      return this.DeriveKeyPair(ikm, extractable)
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
      const dh = nobleKem.decapsulate(
        (pkR as NobleKey).value(priv),
        (ekp.privateKey as NobleKey).value(priv),
      )

      return {
        shared_secret: await deriveSharedSecret(dh, enc, (pkR as NobleKey).value(priv)),
        enc,
      }
    },
    async Decap(enc, skR, pkR) {
      assertNobleKey(skR, algorithm)

      const skRValue = (skR as NobleKey).value(priv)
      pkR ??= (await this.DeserializePublicKey(nobleKem.keygen(skRValue).publicKey)) as NobleKey
      assertNobleKey(pkR, algorithm)

      const pkE = (await this.DeserializePublicKey(enc)) as NobleKey
      const dh = nobleKem.decapsulate(pkE.value(priv), skRValue)

      return deriveSharedSecret(dh, enc, (pkR as NobleKey).value(priv))
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
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
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
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }

    return this.#value.slice()
  }

  seed(_: typeof priv) {
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }

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

interface NobleKEM {
  keygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array }
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array }
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}
