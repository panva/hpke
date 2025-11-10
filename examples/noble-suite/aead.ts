import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import type * as HPKE from '../../index.ts'

export const AEAD_ChaCha20Poly1305: HPKE.AEADFactory = function (): HPKE.AEAD {
  return {
    id: 0x0003,
    type: 'AEAD',
    name: 'ChaCha20Poly1305',
    Nk: 32,
    Nn: 12,
    Nt: 16,
    async Seal(key, nonce, aad, pt) {
      const cipher = chacha20poly1305(key, nonce, aad)
      return cipher.encrypt(pt)
    },
    async Open(key, nonce, aad, ct) {
      const cipher = chacha20poly1305(key, nonce, aad)
      return cipher.decrypt(ct)
    },
  }
}
