import { shake128, shake256 } from '@noble/hashes/sha3.js'
import { turboshake128, turboshake256 } from '@noble/hashes/sha3-addons.js'
import type * as HPKE from '../../index.ts'

export const KDF_SHAKE128: HPKE.KDFFactory = () => createKdf(0x0010, 'SHAKE128', 32, shake128)()

export const KDF_SHAKE256: HPKE.KDFFactory = () => createKdf(0x0011, 'SHAKE256', 64, shake256)()

export const KDF_TurboSHAKE128: HPKE.KDFFactory = () =>
  createKdf(0x0012, 'TurboSHAKE128', 32, turboshake128, { D: 0x1f })()

export const KDF_TurboSHAKE256: HPKE.KDFFactory = () =>
  createKdf(0x0013, 'TurboSHAKE256', 64, turboshake256, { D: 0x1f })()

function createKdf(
  id: number,
  name: string,
  Nh: number,
  derive: (data: Uint8Array, options: { dkLen: number; D?: number }) => Uint8Array,
  options?: { D: number },
): () => HPKE.KDF {
  return function (): HPKE.KDF {
    return {
      id,
      type: 'KDF',
      name,
      Nh,
      stages: 1,
      async Derive(labeled_ikm, L) {
        return derive(labeled_ikm, { dkLen: L, ...options })
      },
      Extract: NotApplicable,
      Expand: NotApplicable,
    }
  }
}

/* c8 ignore next 3 */
const NotApplicable = () => {
  throw new Error('n/a')
}
