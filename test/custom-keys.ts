import it, * as test from 'node:test'
import * as assert from 'node:assert'

import * as HPKE from '../index.ts'
import { NOBLE_KEMS, supported } from './support.ts'

// Find a supported PQ KEM that uses HybridKey
function getSupportedPQKEM(): HPKE.KEMFactory | undefined {
  const pqKEMs: Array<[HPKE.KEMFactory, string]> = [
    [HPKE.KEM_MLKEM768_P256, 'KEM_MLKEM768_P256'],
    [HPKE.KEM_MLKEM1024_P384, 'KEM_MLKEM1024_P384'],
    [HPKE.KEM_MLKEM768_X25519, 'KEM_MLKEM768_X25519'],
  ]
  for (const [kemFactory, name] of pqKEMs) {
    if (supported[name]?.() !== false) {
      return kemFactory
    }
  }
  return undefined
}

// Get a noble KEM that uses NobleKey
function getNobleKEM(): HPKE.KEMFactory | undefined {
  for (const [_id, { factory, supported }] of NOBLE_KEMS) {
    if (supported) {
      return factory
    }
  }
  return undefined
}

const pqKEMFactory = getSupportedPQKEM()!
if (pqKEMFactory) {
  test.describe('HybridKey internal protection', () => {
    async function getHybridKeyPair() {
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
      return await suite.GenerateKeyPair(true)
    }

    it('generates valid HybridKey instances', async () => {
      const kp = await getHybridKeyPair()
      assert.strictEqual(kp.privateKey.type, 'private')
      assert.strictEqual(kp.publicKey.type, 'public')
      assert.strictEqual(kp.privateKey.extractable, true)
      assert.strictEqual(kp.publicKey.extractable, true)
    })

    it('HybridKey constructor is not directly callable', async () => {
      const kp = await getHybridKeyPair()
      const HybridKey = kp.privateKey.constructor as new (...args: unknown[]) => HPKE.Key

      // Trying to call constructor without the private symbol should fail
      assert.throws(() => new HybridKey(Symbol(), { name: 'test' }, 'private', true, null, null), {
        name: 'Error',
        message: 'invalid invocation',
      })
    })

    it('rejects Object.create with HybridKey prototype', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      // Create object with same prototype but no private fields
      const fakeKey = Object.create(Object.getPrototypeOf(kp.privateKey))

      await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
    })

    it('rejects plain object with matching interface', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      const fakeKey = { algorithm: kp.privateKey.algorithm, type: 'private', extractable: true }

      await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
        name: 'TypeError',
      })
    })

    it('rejects spread copy of valid key', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      // Spread loses private fields
      const fakeKey = { ...kp.privateKey }

      await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
        name: 'TypeError',
      })
    })

    it('rejects key with modified prototype', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      // Create a fake key using Object.create
      const fakeKey = Object.create(Object.getPrototypeOf(kp.privateKey), {
        algorithm: { value: kp.privateKey.algorithm, enumerable: true },
        extractable: { value: true, enumerable: true },
        type: { value: 'private', enumerable: true },
      })

      // Change its prototype to something else after creation
      Object.setPrototypeOf(fakeKey, Object.prototype)

      await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
    })

    it('rejects subclass instance that does not call super', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
      const HybridKey = kp.privateKey.constructor as new (...args: unknown[]) => HPKE.Key

      // Create a subclass using function syntax to avoid TypeScript's super() requirement
      function MaliciousSubclass(this: HPKE.Key) {
        return Object.create(HybridKey.prototype, {
          algorithm: { value: kp.privateKey.algorithm, enumerable: true },
          extractable: { value: true, enumerable: true },
          type: { value: 'private', enumerable: true },
        })
      }
      Object.setPrototypeOf(MaliciousSubclass.prototype, HybridKey.prototype)
      Object.setPrototypeOf(MaliciousSubclass, HybridKey)

      const fakeKey = new (MaliciousSubclass as unknown as new () => HPKE.Key)()

      await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
    })

    it('rejects Proxy wrapping a valid key', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      let capturedSymbol: symbol | undefined
      const proxyKey = new Proxy(kp.privateKey, {
        get(target, prop, receiver) {
          if (prop === 'algorithm') {
            return target.algorithm
          }
          if (prop === 'type') {
            return 'private'
          }
          if (prop === 'extractable') {
            return true
          }
          // Try to intercept method calls
          const value = Reflect.get(target, prop, receiver)
          if (typeof value === 'function') {
            return function (guard: symbol) {
              capturedSymbol = guard
              return value.call(target, guard)
            }
          }
          return value
        },
        getPrototypeOf(target) {
          return Object.getPrototypeOf(target)
        },
      })

      await assert.rejects(suite.SerializePrivateKey(proxyKey), { name: 'TypeError' })
      assert.strictEqual(capturedSymbol, undefined, 'Symbol should not have been captured')
    })

    it('cannot override methods on frozen prototype', async () => {
      const kp = await getHybridKeyPair()
      const HybridKey = kp.privateKey.constructor

      // Prototype is frozen, so we cannot override methods
      assert.throws(
        () => {
          ;(HybridKey.prototype as Record<string, unknown>).getPq = function (guard: symbol) {
            console.log('Captured symbol:', guard)
            return null
          }
        },
        { name: 'TypeError' },
      )
    })

    it('cannot add properties to frozen prototype', async () => {
      const kp = await getHybridKeyPair()
      const HybridKey = kp.privateKey.constructor

      assert.throws(
        () => {
          ;(HybridKey.prototype as Record<string, unknown>).malicious = () => {}
        },
        { name: 'TypeError' },
      )
    })

    it('cannot use Object.defineProperty on frozen prototype', async () => {
      const kp = await getHybridKeyPair()
      const HybridKey = kp.privateKey.constructor

      assert.throws(
        () => {
          Object.defineProperty(HybridKey.prototype, 'getPq', {
            value: function (guard: symbol) {
              console.log('Intercepted:', guard)
            },
          })
        },
        { name: 'TypeError' },
      )
    })

    it('private field validation blocks all bypass attempts', async () => {
      const kp = await getHybridKeyPair()
      const suite = new HPKE.CipherSuite(pqKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

      // Verify real key works
      const serialized = await suite.SerializePrivateKey(kp.privateKey)
      assert.ok(serialized)

      // All these should fail because they lack private fields
      const attacks = [
        // Plain object
        { algorithm: kp.privateKey.algorithm, type: 'private', extractable: true },
        // Object.create with prototype
        Object.create(Object.getPrototypeOf(kp.privateKey)),
        // Spread copy (loses private fields)
        { ...kp.privateKey },
      ]

      for (const fakeKey of attacks) {
        await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
          name: 'TypeError',
        })
      }
    })
  })
}

test.describe('NobleKey internal protection', () => {
  const nobleKEMFactory = getNobleKEM()!

  async function getNobleKeyPair() {
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
    return await suite.GenerateKeyPair(true)
  }

  it('generates valid NobleKey instances', async () => {
    const kp = await getNobleKeyPair()
    assert.strictEqual(kp.privateKey.type, 'private')
    assert.strictEqual(kp.publicKey.type, 'public')
    assert.strictEqual(kp.privateKey.extractable, true)
    assert.strictEqual(kp.publicKey.extractable, true)
  })

  it('NobleKey constructor is not directly callable', async () => {
    const kp = await getNobleKeyPair()
    const NobleKey = kp.privateKey.constructor as new (...args: unknown[]) => HPKE.Key

    // Trying to call constructor without the private symbol should fail
    assert.throws(
      () => new NobleKey(Symbol(), 'private', new Uint8Array(), true, { name: 'test' }),
      { name: 'Error', message: 'invalid invocation' },
    )
  })

  it('rejects Object.create with NobleKey prototype', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    // Create object with same prototype but no private fields
    const fakeKey = Object.create(Object.getPrototypeOf(kp.privateKey))

    await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
  })

  it('rejects plain object with matching interface', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    const fakeKey = { algorithm: kp.privateKey.algorithm, type: 'private', extractable: true }

    await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
      name: 'TypeError',
    })
  })

  it('rejects spread copy of valid key', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    // Spread loses private fields
    const fakeKey = { ...kp.privateKey }

    await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
      name: 'TypeError',
    })
  })

  it('rejects key with modified prototype', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    // Create a fake key using Object.create
    const fakeKey = Object.create(Object.getPrototypeOf(kp.privateKey), {
      algorithm: { value: kp.privateKey.algorithm, enumerable: true },
      extractable: { value: true, enumerable: true },
      type: { value: 'private', enumerable: true },
    })

    // Change its prototype to something else after creation
    Object.setPrototypeOf(fakeKey, Object.prototype)

    await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
  })

  it('rejects subclass instance that does not call super', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)
    const NobleKey = kp.privateKey.constructor as new (...args: unknown[]) => HPKE.Key

    // Create a subclass using function syntax to avoid TypeScript's super() requirement
    function MaliciousSubclass(this: HPKE.Key) {
      return Object.create(NobleKey.prototype, {
        algorithm: { value: kp.privateKey.algorithm, enumerable: true },
        extractable: { value: true, enumerable: true },
        type: { value: 'private', enumerable: true },
      })
    }
    Object.setPrototypeOf(MaliciousSubclass.prototype, NobleKey.prototype)
    Object.setPrototypeOf(MaliciousSubclass, NobleKey)

    const fakeKey = new (MaliciousSubclass as unknown as new () => HPKE.Key)()

    await assert.rejects(suite.SerializePrivateKey(fakeKey), { name: 'TypeError' })
  })

  it('rejects Proxy wrapping a valid key', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    let capturedSymbol: symbol | undefined
    const proxyKey = new Proxy(kp.privateKey, {
      get(target, prop, receiver) {
        if (prop === 'algorithm') {
          return target.algorithm
        }
        if (prop === 'type') {
          return 'private'
        }
        if (prop === 'extractable') {
          return true
        }
        // Try to intercept method calls
        const value = Reflect.get(target, prop, receiver)
        if (typeof value === 'function') {
          return function (guard: symbol) {
            capturedSymbol = guard
            return value.call(target, guard)
          }
        }
        return value
      },
      getPrototypeOf(target) {
        return Object.getPrototypeOf(target)
      },
    })

    await assert.rejects(suite.SerializePrivateKey(proxyKey), { name: 'TypeError' })
    assert.strictEqual(capturedSymbol, undefined, 'Symbol should not have been captured')
  })

  it('cannot override methods on frozen prototype', async () => {
    const kp = await getNobleKeyPair()
    const NobleKey = kp.privateKey.constructor

    // Prototype is frozen, so we cannot override methods
    assert.throws(
      () => {
        ;(NobleKey.prototype as Record<string, unknown>).value = function (guard: symbol) {
          console.log('Captured symbol:', guard)
          return null
        }
      },
      { name: 'TypeError' },
    )
  })

  it('cannot add properties to frozen prototype', async () => {
    const kp = await getNobleKeyPair()
    const NobleKey = kp.privateKey.constructor

    assert.throws(
      () => {
        ;(NobleKey.prototype as Record<string, unknown>).malicious = () => {}
      },
      { name: 'TypeError' },
    )
  })

  it('cannot use Object.defineProperty on frozen prototype', async () => {
    const kp = await getNobleKeyPair()
    const NobleKey = kp.privateKey.constructor

    assert.throws(
      () => {
        Object.defineProperty(NobleKey.prototype, 'value', {
          value: function (guard: symbol) {
            console.log('Intercepted:', guard)
          },
        })
      },
      { name: 'TypeError' },
    )
  })

  it('private field validation blocks all bypass attempts', async () => {
    const kp = await getNobleKeyPair()
    const suite = new HPKE.CipherSuite(nobleKEMFactory, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_128_GCM)

    // Verify real key works
    const serialized = await suite.SerializePrivateKey(kp.privateKey)
    assert.ok(serialized)

    // All these should fail because they lack private fields
    const attacks = [
      // Plain object
      { algorithm: kp.privateKey.algorithm, type: 'private', extractable: true },
      // Object.create with prototype
      Object.create(Object.getPrototypeOf(kp.privateKey)),
      // Spread copy (loses private fields)
      { ...kp.privateKey },
    ]

    for (const fakeKey of attacks) {
      await assert.rejects(suite.SerializePrivateKey(fakeKey as unknown as HPKE.Key), {
        name: 'TypeError',
      })
    }
  })
})
