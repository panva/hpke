import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { XWing } from '@noble/post-quantum/hybrid.js'
import { shake256 } from '@noble/hashes/sha3.js'
import type * as HPKE from '../../index.ts'
import { LabeledDerive } from '../../index.ts'

export const KEM_ML_KEM_512: HPKE.KEMFactory = () =>
  createKem(0x0040, 'ML-KEM-512', 32, 768, 800, 64, ml_kem512)()

export const KEM_ML_KEM_768: HPKE.KEMFactory = () =>
  createKem(0x0041, 'ML-KEM-768', 32, 1088, 1184, 64, ml_kem768)()

export const KEM_ML_KEM_1024: HPKE.KEMFactory = () =>
  createKem(0x0042, 'ML-KEM-1024', 32, 1568, 1568, 64, ml_kem1024)()

export const KEM_MLKEM768_X25519: HPKE.KEMFactory = () =>
  createKem(0x647a, 'MLKEM768-X25519', 32, 1120, 1216, 32, XWing)()

function createKem(
  id: number,
  name: string,
  Nsecret: number,
  Nenc: number,
  Npk: number,
  Nsk: number,
  nobleKem: NobleKEM,
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
        const hexId = this.id.toString(16).padStart(4, '0')
        const seed = await LabeledDerive(
          {
            async Derive(ikm, L) {
              return shake256(ikm, { dkLen: L })
            },
          },
          // concat(encode('KEM'), I2OSP(id, 2))
          Uint8Array.of(0x4b, 0x45, 0x4d, +`0x${hexId.slice(0, 2)}`, +`0x${hexId.slice(2, 4)}`), // prettier-ignore
          ikm,
          // encode('DeriveKeyPair')
          Uint8Array.of(0x44, 0x65, 0x72, 0x69, 0x76, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72), // prettier-ignore
          new Uint8Array(),
          this.Nsk,
        )
        const { secretKey, publicKey } = nobleKem.keygen(seed)

        return {
          privateKey: new NobleKey(priv, 'private', secretKey, extractable, algorithm, seed),
          publicKey: new NobleKey(priv, 'public', publicKey, true, algorithm),
        }
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
        return key.seed(priv)
      },
      async DeserializePrivateKey(key, extractable) {
        const { secretKey } = nobleKem.keygen(key)

        return new NobleKey(priv, 'private', secretKey, extractable, algorithm, key.slice())
      },
      async Encap(pkR) {
        assertNobleKey(pkR, algorithm)
        const { cipherText, sharedSecret } = nobleKem.encapsulate(pkR.value(priv))
        return { shared_secret: sharedSecret, enc: cipherText }
      },
      async Decap(enc, skR) {
        assertNobleKey(skR, algorithm)
        return nobleKem.decapsulate(enc, skR.value(priv))
      },
    }
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

interface NobleKEM {
  keygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array }
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array }
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}
