// Checks the package against Node.js WebCrypto types without the DOM library.
import type { webcrypto } from 'node:crypto'

import * as HPKE from 'hpke'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isNodeCryptoKey: Equals<HPKE.CryptoKey, webcrypto.CryptoKey> = true

async function nodeWebCryptoKeys() {
  const suite = new HPKE.CipherSuite(HPKE.KEM_ML_KEM_768, HPKE.KDF_SHAKE256, HPKE.AEAD_AES_128_GCM)
  const pair = await suite.GenerateKeyPair()
  const _publicKey: webcrypto.CryptoKey = pair.publicKey
  const _privateKey: webcrypto.CryptoKey = pair.privateKey
}
