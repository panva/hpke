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

function createAlgorithmMap<T extends HPKE.KDFFactory | HPKE.KEMFactory | HPKE.AEADFactory>(
  type: string,
) {
  const map = new Map<number, { supported: boolean; factory: T; name: string }>()

  const hpkeAlgorithms = Object.values(HPKE).filter(
    (value) => typeof value === 'function' && value.name.startsWith(`${type}_`),
  ) as T[]
  const nobleAlgorithms = Object.values(noble).filter(
    (value) => typeof value === 'function' && value.name.startsWith(`${type}_`),
  ) as T[]

  // Process HPKE algorithms first
  for (const algorithm of hpkeAlgorithms) {
    const id = IDs[algorithm.name]
    if (!id) throw new Error(`missing id for ${algorithm.name}`)

    const isSupported = supported[algorithm.name]?.() !== false

    map.set(id, {
      factory: algorithm,
      supported: isSupported,
      name: algorithm.name,
    })
  }

  // Process noble algorithms - these are always supported and only overwrite if existing is not supported
  for (const algorithm of nobleAlgorithms) {
    const id = IDs[algorithm.name]
    if (!id) throw new Error(`missing id for ${algorithm.name}`)

    const existing = map.get(id)

    // Only overwrite if there's no existing entry, or if the existing one is not supported
    if (!existing || !existing.supported) {
      map.set(id, {
        factory: algorithm,
        supported: true, // noble implementations are always supported
        name: algorithm.name,
      })
    }
  }

  return map
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
      unsupported.push({
        factory: algorithm,
        name: algorithm.name,
      })
    }
  }

  return unsupported
}

export const KEMS = createAlgorithmMap<HPKE.KEMFactory>('KEM')
export const KDFS = createAlgorithmMap<HPKE.KDFFactory>('KDF')
export const AEADS = createAlgorithmMap<HPKE.AEADFactory>('AEAD')

export const UNSUPPORTED_KEMS = getUnsupportedAlgorithms<HPKE.KEMFactory>('KEM')
export const UNSUPPORTED_KDFS = getUnsupportedAlgorithms<HPKE.KDFFactory>('KDF')
export const UNSUPPORTED_AEADS = getUnsupportedAlgorithms<HPKE.AEADFactory>('AEAD')
