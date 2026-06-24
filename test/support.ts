import * as HPKE from '../index.ts'
import * as noble from '../examples/noble-suite/index.ts'
import { ALGORITHM_IDS, isUsable } from './run.js'

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

export const IDs = ALGORITHM_IDS

export const supported: Record<string, () => boolean | undefined> = Object.fromEntries(
  Object.keys(IDs).map((name) => [name, () => isUsable(name)]),
)

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
    const isSupported = isUsable(algorithm.name)
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
