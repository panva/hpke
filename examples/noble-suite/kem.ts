import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { XWing, ecdhKem } from '@noble/post-quantum/hybrid.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { x448 } from '@noble/curves/ed448.js'
import { shake256 } from '@noble/hashes/sha3.js'
import type * as HPKE from '../../index.ts'
import {
  LabeledDerive,
  LabeledExtract,
  LabeledExpand,
  KDF_HKDF_SHA256,
  KDF_HKDF_SHA512,
  concat,
  encode,
  I2OSP,
} from '../../index.ts'

export const KEM_DHKEM_X25519_HKDF_SHA256: HPKE.KEMFactory = () =>
  createDhKem(
    0x0020,
    'DHKEM(X25519, HKDF-SHA256)',
    32,
    32,
    32,
    32,
    ecdhKem(x25519),
    KDF_HKDF_SHA256,
  )()

export const KEM_DHKEM_X448_HKDF_SHA512: HPKE.KEMFactory = () =>
  createDhKem(0x0021, 'DHKEM(X448, HKDF-SHA512)', 64, 56, 56, 56, ecdhKem(x448), KDF_HKDF_SHA512)()

export const KEM_ML_KEM_512: HPKE.KEMFactory = () =>
  createPqKem(0x0040, 'ML-KEM-512', 32, 768, 800, 64, ml_kem512)()

export const KEM_ML_KEM_768: HPKE.KEMFactory = () =>
  createPqKem(0x0041, 'ML-KEM-768', 32, 1088, 1184, 64, ml_kem768)()

export const KEM_ML_KEM_1024: HPKE.KEMFactory = () =>
  createPqKem(0x0042, 'ML-KEM-1024', 32, 1568, 1568, 64, ml_kem1024)()

export const KEM_MLKEM768_X25519: HPKE.KEMFactory = () =>
  createPqKem(0x647a, 'MLKEM768-X25519', 32, 1120, 1216, 32, XWing)()

function createKem(
  id: number,
  name: string,
  Nsecret: number,
  Nenc: number,
  Npk: number,
  Nsk: number,
  nobleKem: NobleKEM,
  impl: Implementation,
): HPKE.KEMFactory {
  Object.freeze(NobleKey.prototype)
  return function (): HPKE.KEM {
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
        return impl.DeriveKeyPair(this, nobleKem, ikm, extractable, algorithm)
      },
      async GenerateKeyPair(extractable) {
        const ikm = crypto.getRandomValues(new Uint8Array(this.Nsk))
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
        return impl.SerializePrivateKey(this, key)
      },
      async DeserializePrivateKey(key, extractable) {
        return impl.DeserializePrivateKey(this, nobleKem, key, extractable, algorithm)
      },
      async Encap(pkR) {
        assertNobleKey(pkR, algorithm)
        return impl.Encap(this, nobleKem, pkR, algorithm)
      },
      async Decap(enc, skR, pkR) {
        assertNobleKey(skR, algorithm)
        return impl.Decap(this, nobleKem, enc, skR, pkR, algorithm)
      },
    }
  }
}

function createPqKem(
  id: number,
  name: string,
  Nsecret: number,
  Nenc: number,
  Npk: number,
  Nsk: number,
  nobleKem: NobleKEM,
): HPKE.KEMFactory {
  return createKem(id, name, Nsecret, Nenc, Npk, Nsk, nobleKem, {
    async DeriveKeyPair(kem, nobleKem, ikm, extractable, algorithm) {
      const seed = await LabeledDerive(
        {
          async Derive(ikm, L) {
            return shake256(ikm, { dkLen: L })
          },
        },
        concat(encode('KEM'), I2OSP(id, 2)),
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        kem.Nsk,
      )
      const { secretKey, publicKey } = nobleKem.keygen(seed)

      return {
        privateKey: new NobleKey(priv, 'private', secretKey, extractable, algorithm, seed),
        publicKey: new NobleKey(priv, 'public', publicKey, true, algorithm),
      }
    },
    async SerializePrivateKey(_kem, key) {
      return (key as NobleKey).seed(priv)
    },
    async DeserializePrivateKey(_kem, nobleKem, key, extractable, algorithm) {
      const { secretKey } = nobleKem.keygen(key)
      return new NobleKey(priv, 'private', secretKey, extractable, algorithm, key.slice())
    },
    async Encap(_kem, nobleKem, pkR) {
      const { cipherText, sharedSecret } = nobleKem.encapsulate((pkR as NobleKey).value(priv))
      return { shared_secret: sharedSecret, enc: cipherText }
    },
    async Decap(_kem, nobleKem, enc, skR) {
      return nobleKem.decapsulate(enc, (skR as NobleKey).value(priv))
    },
  })
}

function createDhKem(
  id: number,
  name: string,
  Nsecret: number,
  Nenc: number,
  Npk: number,
  Nsk: number,
  nobleKem: NobleKEM,
  kdfFactory: HPKE.KDFFactory,
): HPKE.KEMFactory {
  const kdf = kdfFactory()
  const suite_id = concat(encode('KEM'), I2OSP(id, 2))

  return createKem(id, name, Nsecret, Nenc, Npk, Nsk, nobleKem, {
    async DeriveKeyPair(kem, nobleKem, ikm, extractable, algorithm) {
      const dkp_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('dkp_prk'), ikm)
      const sk = await LabeledExpand(
        kdf,
        suite_id,
        dkp_prk,
        encode('sk'),
        new Uint8Array(),
        kem.Nsk,
      )
      const { secretKey, publicKey } = nobleKem.keygen(sk)

      return {
        privateKey: new NobleKey(priv, 'private', secretKey, extractable, algorithm),
        publicKey: new NobleKey(priv, 'public', publicKey, true, algorithm),
      }
    },
    async DeserializePrivateKey(_kem, _nobleKem, key, extractable, algorithm) {
      return new NobleKey(priv, 'private', key.slice(), extractable, algorithm)
    },
    async SerializePrivateKey(_kem, key) {
      return (key as NobleKey).value(priv)
    },
    async Encap(kem, nobleKem, pkR) {
      // Generate ephemeral key pair
      const ekp = await kem.GenerateKeyPair(false)
      const skE = ekp.privateKey as NobleKey
      const pkE = ekp.publicKey as NobleKey

      // Perform DH
      const dh = nobleKem.decapsulate((pkR as NobleKey).value(priv), skE.value(priv))

      // DHKEM encapsulation
      const enc = pkE.value(priv)
      const pkRm = (pkR as NobleKey).value(priv)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('eae_prk'), dh)
      const shared_secret = await LabeledExpand(
        kdf,
        suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        kem.Nsecret,
      )

      return { shared_secret, enc }
    },
    async Decap(kem, nobleKem, enc, skR, pkR) {
      pkR ??= (await kem.DeserializePublicKey(
        nobleKem.keygen((skR as NobleKey).value(priv)).publicKey,
      )) as NobleKey

      // Deserialize encapsulated key
      const pkE = (await kem.DeserializePublicKey(enc)) as NobleKey

      // Perform DH
      const dh = nobleKem.decapsulate(pkE.value(priv), (skR as NobleKey).value(priv))

      // DHKEM decapsulation
      const pkRm = (pkR as NobleKey).value(priv)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(kdf, suite_id, new Uint8Array(), encode('eae_prk'), dh)
      const shared_secret = await LabeledExpand(
        kdf,
        suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        kem.Nsecret,
      )

      return shared_secret
    },
  })
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

interface NobleKEM {
  keygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array }
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array }
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}

type Implementation = {
  DeriveKeyPair: (
    kem: HPKE.KEM,
    nobleKem: NobleKEM,
    ikm: Uint8Array,
    extractable: boolean,
    algorithm: KeyAlgorithm,
  ) => Promise<HPKE.KeyPair>
  SerializePrivateKey: (kem: HPKE.KEM, key: HPKE.Key) => Promise<Uint8Array>
  DeserializePrivateKey: (
    kem: HPKE.KEM,
    nobleKem: NobleKEM,
    key: Uint8Array,
    extractable: boolean,
    algorithm: KeyAlgorithm,
  ) => Promise<HPKE.Key>
  Encap: (
    kem: HPKE.KEM,
    nobleKem: NobleKEM,
    pkR: HPKE.Key,
    algorithm: KeyAlgorithm,
  ) => Promise<{ shared_secret: Uint8Array; enc: Uint8Array }>
  Decap: (
    kem: HPKE.KEM,
    nobleKem: NobleKEM,
    enc: Uint8Array,
    skR: HPKE.Key,
    pkR: HPKE.Key | undefined,
    algorithm: KeyAlgorithm,
  ) => Promise<Uint8Array>
}
