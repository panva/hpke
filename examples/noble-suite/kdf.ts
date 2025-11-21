import { shake128, shake256 } from '@noble/hashes/sha3.js'
import { turboshake128, turboshake256 } from '@noble/hashes/sha3-addons.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import type * as HPKE from '../../index.ts'

export const KDF_HKDF_SHA256: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0001, 'HKDF-SHA256', 32, sha256)

export const KDF_HKDF_SHA384: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0002, 'HKDF-SHA384', 48, sha384)

export const KDF_HKDF_SHA512: HPKE.KDFFactory = () =>
  createTwoStageKdf(0x0003, 'HKDF-SHA512', 64, sha512)

export const KDF_SHAKE128: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0010, 'SHAKE128', 32, shake128)

export const KDF_SHAKE256: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0011, 'SHAKE256', 64, shake256)

export const KDF_TurboSHAKE128: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0012, 'TurboSHAKE128', 32, turboshake128, 0x1f)

export const KDF_TurboSHAKE256: HPKE.KDFFactory = () =>
  createOneStageKdf(0x0013, 'TurboSHAKE256', 64, turboshake256, 0x1f)

function createTwoStageKdf(
  id: number,
  name: string,
  Nh: number,
  hash: typeof sha256 | typeof sha384 | typeof sha512,
): HPKE.KDF {
  return {
    id,
    type: 'KDF',
    name,
    Nh,
    stages: 2,
    async Extract(salt, ikm) {
      return extract(hash, ikm, salt)
    },
    async Expand(prk, info, L) {
      return expand(hash, prk, info, L)
    },
    Derive: NotApplicable,
  }
}

function createOneStageKdf(
  id: number,
  name: string,
  Nh: number,
  derive: typeof shake128 | typeof shake256 | typeof turboshake128 | typeof turboshake256,
  D?: number,
): HPKE.KDF {
  return {
    id,
    type: 'KDF',
    name,
    Nh,
    stages: 1,
    async Derive(labeled_ikm, L) {
      return derive(labeled_ikm, { dkLen: L, D })
    },
    Extract: NotApplicable,
    Expand: NotApplicable,
  }
}

/* c8 ignore next 3 */
const NotApplicable = () => {
  throw new Error('unreachable')
}
