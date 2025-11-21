import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { gcm } from '@noble/ciphers/aes.js'
import type * as HPKE from '../../index.ts'

export const AEAD_AES_128_GCM: HPKE.AEADFactory = () => createAead(0x0001, 'AES-128-GCM', 16, gcm)()

export const AEAD_AES_256_GCM: HPKE.AEADFactory = () => createAead(0x0002, 'AES-256-GCM', 32, gcm)()

export const AEAD_ChaCha20Poly1305: HPKE.AEADFactory = () =>
  createAead(0x0003, 'ChaCha20Poly1305', 32, chacha20poly1305)()

function createAead(
  id: number,
  name: string,
  Nk: number,
  cipher: typeof chacha20poly1305 | typeof gcm,
): HPKE.AEADFactory {
  return (): HPKE.AEAD => {
    return {
      id,
      type: 'AEAD',
      name,
      Nk,
      Nn: 12,
      Nt: 16,
      async Seal(key, nonce, aad, pt) {
        return cipher(key, nonce, aad).encrypt(pt)
      },
      async Open(key, nonce, aad, ct) {
        return cipher(key, nonce, aad).decrypt(ct)
      },
    }
  }
}
