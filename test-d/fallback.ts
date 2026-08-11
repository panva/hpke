// Selects the CryptoKey structural fallback by compiling without DOM or Node ambient types.
import * as HPKE from 'hpke'

declare global {
  abstract class CryptoKey {
    readonly type: string
    readonly extractable: boolean
    readonly algorithm: { name: string }
    readonly usages: string[]
  }

  interface CryptoKeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
  }

  interface SubtleCrypto {
    generateKey(
      algorithm: string,
      extractable: boolean,
      keyUsages: string[],
    ): Promise<CryptoKey | CryptoKeyPair>
    exportKey(format: string, key: CryptoKey): Promise<ArrayBuffer>
  }

  interface Crypto {
    readonly subtle: SubtleCrypto
  }

  const crypto: Crypto
}

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _algorithm: Equals<HPKE.CryptoKey['algorithm'], { name: string }> = true
const _extractable: Equals<HPKE.CryptoKey['extractable'], boolean> = true
const _type: Equals<HPKE.CryptoKey['type'], string> = true
const _usages: Equals<HPKE.CryptoKey['usages'], string[]> = true

// @ts-expect-error the fallback must not degrade to any
const _notAny: HPKE.CryptoKey = 'definitely not a key'

declare const key: CryptoKey
declare const hpkeKey: HPKE.CryptoKey

const _hostKey: HPKE.CryptoKey = key
const _fallbackKey: CryptoKey = hpkeKey
const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)
suite.SetupSender(key)

async function fallbackKeys() {
  const pair = await suite.GenerateKeyPair()
  const _hostPair: CryptoKeyPair = pair
  await crypto.subtle.exportKey('raw', pair.publicKey)
}
