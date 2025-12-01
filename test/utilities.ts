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

  test.describe('I2OSP', () => {
    // Realistic scenarios - values actually used in HPKE
    test.describe('realistic HPKE usage', () => {
      it('converts algorithm identifiers (2 bytes)', () => {
        // KEM IDs: 0x0010-0x0021, 0x0040-0x0042, 0x0050-0x0051
        assert.deepEqual(HPKE.I2OSP(0x0010, 2), Uint8Array.of(0x00, 0x10))
        assert.deepEqual(HPKE.I2OSP(0x0021, 2), Uint8Array.of(0x00, 0x21))
        // KDF IDs: 0x0001-0x0003, 0x0010-0x0011
        assert.deepEqual(HPKE.I2OSP(0x0001, 2), Uint8Array.of(0x00, 0x01))
        // AEAD IDs: 0x0001-0x0003, 0xFFFF
        assert.deepEqual(HPKE.I2OSP(0xffff, 2), Uint8Array.of(0xff, 0xff))
      })

      it('converts mode identifiers (1 byte)', () => {
        assert.deepEqual(HPKE.I2OSP(0x00, 1), Uint8Array.of(0x00)) // MODE_BASE
        assert.deepEqual(HPKE.I2OSP(0x01, 1), Uint8Array.of(0x01)) // MODE_PSK
      })

      it('converts length prefixes (2 bytes)', () => {
        assert.deepEqual(HPKE.I2OSP(0, 2), Uint8Array.of(0x00, 0x00))
        assert.deepEqual(HPKE.I2OSP(32, 2), Uint8Array.of(0x00, 0x20))
        assert.deepEqual(HPKE.I2OSP(65535, 2), Uint8Array.of(0xff, 0xff))
      })

      it('converts typical sequence numbers for nonce computation (12 bytes)', () => {
        // Early messages
        assert.deepEqual(HPKE.I2OSP(0, 12), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        assert.deepEqual(HPKE.I2OSP(1, 12), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
        assert.deepEqual(HPKE.I2OSP(255, 12), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255))
        assert.deepEqual(HPKE.I2OSP(256, 12), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0))
      })
    })

    // Boundary conditions
    test.describe('boundary conditions', () => {
      it('handles byte boundaries', () => {
        // 1-byte max
        assert.deepEqual(HPKE.I2OSP(255, 1), Uint8Array.of(255))
        // 2-byte boundary
        assert.deepEqual(HPKE.I2OSP(255, 2), Uint8Array.of(0, 255))
        assert.deepEqual(HPKE.I2OSP(256, 2), Uint8Array.of(1, 0))
        // 4-byte max
        assert.deepEqual(HPKE.I2OSP(0xffffffff, 4), Uint8Array.of(255, 255, 255, 255))
      })

      it('handles 32-bit boundary (critical for bit shift operations)', () => {
        // Max 32-bit unsigned - last value safe for >>> operator
        assert.deepEqual(
          HPKE.I2OSP(0xffffffff, 12),
          Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255),
        )
        // First value beyond 32-bit - would fail with >> or >>> operators
        assert.deepEqual(
          HPKE.I2OSP(0x100000000, 12),
          Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
        )
        // Just above 32-bit boundary
        assert.deepEqual(
          HPKE.I2OSP(0x100000001, 12),
          Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1),
        )
        assert.deepEqual(
          HPKE.I2OSP(0x1ffffffff, 12),
          Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1, 255, 255, 255, 255),
        )
      })

      it('handles MAX_SAFE_INTEGER (JavaScript precision limit)', () => {
        // MAX_SAFE_INTEGER = 2^53 - 1 = 9007199254740991 = 0x1FFFFFFFFFFFFF
        assert.deepEqual(
          HPKE.I2OSP(Number.MAX_SAFE_INTEGER, 12),
          Uint8Array.of(0, 0, 0, 0, 0, 31, 255, 255, 255, 255, 255, 255),
        )
      })

      it('pads with leading zeros when w exceeds required bytes', () => {
        assert.deepEqual(HPKE.I2OSP(1, 4), Uint8Array.of(0, 0, 0, 1))
        assert.deepEqual(HPKE.I2OSP(256, 4), Uint8Array.of(0, 0, 1, 0))
      })
    })

    // Edge cases and error conditions
    test.describe('edge cases', () => {
      it('handles zero', () => {
        assert.deepEqual(HPKE.I2OSP(0, 1), Uint8Array.of(0))
        assert.deepEqual(HPKE.I2OSP(0, 4), Uint8Array.of(0, 0, 0, 0))
        assert.deepEqual(HPKE.I2OSP(0, 12), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      })

      it('throws for w <= 0', () => {
        assert.throws(() => HPKE.I2OSP(0, 0), /w must be a positive safe integer/)
        assert.throws(() => HPKE.I2OSP(0, -1), /w must be a positive safe integer/)
      })

      it('throws for non-integer w', () => {
        assert.throws(() => HPKE.I2OSP(0, 1.5), /w must be a positive safe integer/)
        assert.throws(() => HPKE.I2OSP(0, NaN), /w must be a positive safe integer/)
        assert.throws(() => HPKE.I2OSP(0, Infinity), /w must be a positive safe integer/)
      })

      it('throws for negative n', () => {
        assert.throws(() => HPKE.I2OSP(-1, 4), /n must be a non-negative safe integer/)
        assert.throws(() => HPKE.I2OSP(-256, 4), /n must be a non-negative safe integer/)
      })

      it('throws for non-integer n', () => {
        assert.throws(() => HPKE.I2OSP(1.5, 4), /n must be a non-negative safe integer/)
        assert.throws(() => HPKE.I2OSP(NaN, 4), /n must be a non-negative safe integer/)
        assert.throws(() => HPKE.I2OSP(Infinity, 4), /n must be a non-negative safe integer/)
      })

      it('throws when n exceeds capacity of w bytes', () => {
        assert.throws(() => HPKE.I2OSP(256, 1), /n too large to fit in w-length byte string/)
        assert.throws(() => HPKE.I2OSP(65536, 2), /n too large to fit in w-length byte string/)
        assert.throws(
          () => HPKE.I2OSP(0x100000000, 4),
          /n too large to fit in w-length byte string/,
        )
      })
    })
  })
})
