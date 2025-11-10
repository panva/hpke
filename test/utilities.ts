import it, * as test from 'node:test'
import { strict as assert } from 'node:assert'

import * as HPKE from '../index.ts'

const concat = (...args: Uint8Array[]) => new Uint8Array(Buffer.concat(args))

test.describe('Utilities', () => {
  test.describe('LabeledDerive', () => {
    it('calls Derive with correctly formatted labeled_ikm', async () => {
      const suite_id = new Uint8Array([1, 2, 3])
      const ikm = new Uint8Array([10, 20, 30])
      const label = Uint8Array.of(116, 101, 115, 116, 45, 108, 97, 98, 101, 108)
      const context = new Uint8Array([40, 50])
      const L = 32

      const mockReturn = new Uint8Array(32).fill(0xff)

      const mockKDF: Pick<HPKE.KDF, 'Derive'> = {
        async Derive(labeled_ikm: Uint8Array, length: number): Promise<Uint8Array> {
          // Verify labeled_ikm is constructed correctly:
          // concat(ikm, encode('HPKE-v1'), suite_id, lengthPrefixed(label), I2OSP(L, 2), context)
          // lengthPrefixed(label) = I2OSP(10, 2) + label = [0, 10] + label bytes
          const expectedLabeledIkm = concat(
            ikm,
            Uint8Array.of(72, 80, 75, 69, 45, 118, 49),
            suite_id,
            Uint8Array.of(0x00, 0x0a),
            label,
            Uint8Array.of(0x00, 0x20),
            context,
          )
          assert.deepEqual(labeled_ikm, expectedLabeledIkm)

          // Verify Derive was called with correct length
          assert.equal(length, L)

          return mockReturn
        },
      }

      const result = await HPKE.LabeledDerive(mockKDF, suite_id, ikm, label, context, L)

      assert.equal(result, mockReturn)
    })
  })

  test.describe('LabeledExtract', () => {
    it('calls Extract with correctly formatted labeled_ikm', async () => {
      const suite_id = new Uint8Array([1, 2, 3])
      const salt = new Uint8Array([10, 20])
      const label = Uint8Array.of(116, 101, 115, 116, 45, 108, 97, 98, 101, 108)
      const ikm = new Uint8Array([30, 40, 50])

      const mockReturn = new Uint8Array([0xaa, 0xbb, 0xcc])

      const mockKDF: Pick<HPKE.KDF, 'Extract'> = {
        async Extract(s: Uint8Array, labeled_ikm: Uint8Array): Promise<Uint8Array> {
          // Verify Extract was called with correct salt
          assert.equal(s, salt)

          // Verify labeled_ikm is constructed correctly:
          // concat(encode('HPKE-v1'), suite_id, label, ikm)
          const expectedLabeledIkm = concat(
            Uint8Array.of(72, 80, 75, 69, 45, 118, 49),
            suite_id,
            label,
            ikm,
          )
          assert.deepEqual(labeled_ikm, expectedLabeledIkm)

          return mockReturn
        },
      }

      const result = await HPKE.LabeledExtract(mockKDF, suite_id, salt, label, ikm)

      assert.equal(result, mockReturn)
    })
  })

  test.describe('LabeledExpand', () => {
    it('calls Expand with correctly formatted labeled_info', async () => {
      const suite_id = new Uint8Array([1, 2, 3])
      const prk = new Uint8Array([10, 20, 30])
      const label = Uint8Array.of(116, 101, 115, 116, 45, 108, 97, 98, 101, 108)
      const info = new Uint8Array([40, 50])
      const L = 32

      const mockReturn = new Uint8Array(32).fill(0xdd)

      const mockKDF: Pick<HPKE.KDF, 'Expand'> = {
        async Expand(p: Uint8Array, labeled_info: Uint8Array, length: number): Promise<Uint8Array> {
          // Verify Expand was called with correct prk
          assert.equal(p, prk)

          // Verify Expand was called with correct length
          assert.equal(length, L)

          // Verify labeled_info is constructed correctly:
          // concat(I2OSP(L, 2), encode('HPKE-v1'), suite_id, label, info)
          const expectedLabeledInfo = concat(
            Uint8Array.of(0x00, 0x20),
            Uint8Array.of(72, 80, 75, 69, 45, 118, 49),
            suite_id,
            label,
            info,
          )
          assert.deepEqual(labeled_info, expectedLabeledInfo)

          return mockReturn
        },
      }

      const result = await HPKE.LabeledExpand(mockKDF, suite_id, prk, label, info, L)

      assert.equal(result, mockReturn)
    })
  })
})
