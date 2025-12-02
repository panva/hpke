import * as HPKE from '../index.ts'
import * as noble from '../examples/noble-suite/index.ts'

export function label(suite: HPKE.CipherSuite, mode: number) {
  const modeStr =
    mode === 0x00 ? 'Base' : mode === 0x01 ? 'PSK' : mode === 0x02 ? 'Auth' : 'AuthPSK'
  return `${suite.KEM.name}, ${suite.KDF.name}, ${suite.AEAD.name}, ${modeStr}`
}

export function hex(str: string): Uint8Array {
  return (
    // @ts-ignore
    Uint8Array.fromHex?.(str) ||
    (() => {
      const buf = Buffer.allocUnsafe(str.length / 2)
      buf.write(str, 'hex')
      return new Uint8Array(buf)
    })()
  )
}

// Shim for t.waitFor which is not available in Deno and Bun
export async function waitFor(
  fn: () => void | Promise<void>,
  options?: { interval?: number; timeout?: number; signal?: AbortSignal },
): Promise<void> {
  const interval = options?.interval ?? 50
  const signal = options?.signal ?? AbortSignal.timeout(options?.timeout ?? 1000)

  if (signal?.aborted) {
    throw new Error('waitFor timeout exceeded')
  }

  try {
    await fn()
  } catch {
    await new Promise((resolve) => setTimeout(resolve, interval))
    return waitFor(fn, { interval, signal })
  }
}

export const IDs: Record<string, number> = {
  KDF_HKDF_SHA256: 0x0001,
  KDF_HKDF_SHA384: 0x0002,
  KDF_HKDF_SHA512: 0x0003,
  KDF_SHAKE128: 0x0010,
  KDF_SHAKE256: 0x0011,
  KDF_TurboSHAKE128: 0x0012,
  KDF_TurboSHAKE256: 0x0013,
  KEM_DHKEM_P256_HKDF_SHA256: 0x0010,
  KEM_DHKEM_P384_HKDF_SHA384: 0x0011,
  KEM_DHKEM_P521_HKDF_SHA512: 0x0012,
  KEM_DHKEM_X25519_HKDF_SHA256: 0x0020,
  KEM_DHKEM_X448_HKDF_SHA512: 0x0021,
  KEM_ML_KEM_512: 0x0040,
  KEM_ML_KEM_768: 0x0041,
  KEM_ML_KEM_1024: 0x0042,
  KEM_MLKEM768_P256: 0x0050,
  KEM_MLKEM1024_P384: 0x0051,
  KEM_MLKEM768_X25519: 0x647a,
  AEAD_AES_128_GCM: 0x0001,
  AEAD_AES_256_GCM: 0x0002,
  AEAD_ChaCha20Poly1305: 0x0003,
  AEAD_EXPORT_ONLY: 0xffff,
}

function supports(op: string, algorithm: AlgorithmIdentifier & { length?: number }) {
  // @ts-expect-error
  return SubtleCrypto.supports?.(op, algorithm) ?? false
}

export const supported: Record<string, () => boolean | undefined> = {
  KDF_SHAKE128() {
    return supports('digest', { name: 'cSHAKE128', length: 512 })
  },
  KDF_SHAKE256() {
    return supports('digest', { name: 'cSHAKE256', length: 512 })
  },
  KEM_ML_KEM_512() {
    return supports('generateKey', 'ML-KEM-512')
  },
  KEM_ML_KEM_768() {
    return supports('generateKey', 'ML-KEM-768')
  },
  KEM_ML_KEM_1024() {
    return supports('generateKey', 'ML-KEM-1024')
  },
  KEM_MLKEM768_P256() {
    return supports('generateKey', 'ML-KEM-512')
  },
  KEM_MLKEM1024_P384() {
    return supports('generateKey', 'ML-KEM-768')
  },
  KEM_MLKEM768_X25519() {
    return supports('generateKey', 'ML-KEM-1024')
  },
  AEAD_ChaCha20Poly1305() {
    return supports('generateKey', 'ChaCha20-Poly1305')
  },
  KEM_DHKEM_X25519_HKDF_SHA256() {
    // @ts-ignore
    return typeof Bun !== 'object'
  },
  KEM_DHKEM_X448_HKDF_SHA512() {
    // @ts-ignore
    return typeof Deno !== 'object' && typeof Bun !== 'object'
  },
  KEM_DHKEM_P521_HKDF_SHA512() {
    // @ts-ignore
    return typeof Deno !== 'object'
  },
}

type AlgorithmEntry<T> = {
  supported: boolean
  factory: T
  name: string
  impl: 'webcrypto' | 'noble'
}

function createAlgorithmMaps<T extends HPKE.KDFFactory | HPKE.KEMFactory | HPKE.AEADFactory>(
  type: string,
) {
  // Map that prefers WebCrypto, falls back to Noble
  const preferWebCrypto = new Map<number, AlgorithmEntry<T>>()
  // Map that only contains Noble implementations
  const onlyNoble = new Map<number, AlgorithmEntry<T>>()

  const hpkeAlgorithms = Object.values(HPKE).filter(
    (value) => typeof value === 'function' && value.name.startsWith(`${type}_`),
  ) as T[]
  const nobleAlgorithms = Object.values(noble).filter(
    (value) => typeof value === 'function' && value.name.startsWith(`${type}_`),
  ) as T[]

  // Process HPKE (WebCrypto) algorithms first
  for (const algorithm of hpkeAlgorithms) {
    const id = IDs[algorithm.name]
    if (!id) throw new Error(`missing id for ${algorithm.name}`)

    const isSupported = supported[algorithm.name]?.() !== false

    preferWebCrypto.set(id, {
      factory: algorithm,
      supported: isSupported,
      name: algorithm.name,
      impl: 'webcrypto',
    })
  }

  // Process noble algorithms
  for (const algorithm of nobleAlgorithms) {
    const id = IDs[algorithm.name]
    if (!id) throw new Error(`missing id for ${algorithm.name}`)

    // Always add to onlyNoble map
    onlyNoble.set(id, { factory: algorithm, supported: true, name: algorithm.name, impl: 'noble' })

    // For preferWebCrypto: only overwrite if there's no existing entry, or if the existing one is not supported
    const existing = preferWebCrypto.get(id)
    if (!existing || !existing.supported) {
      preferWebCrypto.set(id, {
        factory: algorithm,
        supported: true,
        name: algorithm.name,
        impl: 'noble',
      })
    }
  }

  return { preferWebCrypto, onlyNoble }
}

function getUnsupportedAlgorithms<T extends HPKE.KDFFactory | HPKE.KEMFactory | HPKE.AEADFactory>(
  type: string,
) {
  const unsupported: Array<{ factory: T; name: string }> = []

  const hpkeAlgorithms = Object.values(HPKE).filter(
    (value) => typeof value === 'function' && value.name.startsWith(`${type}_`),
  ) as T[]

  for (const algorithm of hpkeAlgorithms) {
    const isSupported = supported[algorithm.name]?.() !== false
    if (!isSupported) {
      unsupported.push({ factory: algorithm, name: algorithm.name })
    }
  }

  return unsupported
}

const kemMaps = createAlgorithmMaps<HPKE.KEMFactory>('KEM')
const kdfMaps = createAlgorithmMaps<HPKE.KDFFactory>('KDF')
const aeadMaps = createAlgorithmMaps<HPKE.AEADFactory>('AEAD')

// Add AEAD_EXPORT_ONLY from WebCrypto to Noble AEADs
aeadMaps.onlyNoble.set(IDs.AEAD_EXPORT_ONLY!, {
  factory: HPKE.AEAD_EXPORT_ONLY,
  supported: true,
  name: 'AEAD_EXPORT_ONLY',
  impl: 'noble',
})

export const KEMS = kemMaps.preferWebCrypto
export const KDFS = kdfMaps.preferWebCrypto
export const AEADS = aeadMaps.preferWebCrypto

export const NOBLE_KEMS = kemMaps.onlyNoble
export const NOBLE_KDFS = kdfMaps.onlyNoble
export const NOBLE_AEADS = aeadMaps.onlyNoble

export const UNSUPPORTED_KEMS = getUnsupportedAlgorithms<HPKE.KEMFactory>('KEM')
export const UNSUPPORTED_KDFS = getUnsupportedAlgorithms<HPKE.KDFFactory>('KDF')
export const UNSUPPORTED_AEADS = getUnsupportedAlgorithms<HPKE.AEADFactory>('AEAD')
