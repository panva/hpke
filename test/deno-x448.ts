import it, * as test from 'node:test'
import * as assert from 'node:assert'
import { Buffer } from 'node:buffer'

// @ts-expect-error
const isDeno = typeof Deno === 'object'

test.describe('Deno native X448 conformance sentinel', () => {
  it(
    'still fails the HPKE X448 public key known-answer test',
    { skip: isDeno ? false : 'only runs on Deno' },
    async () => {
      const pkcs8 = Uint8Array.fromHex('3046020100300506032b656f043a0438')
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        Buffer.concat([
          pkcs8,
          Uint8Array.fromHex(
            '27a4354608f3bdd38f1f5af305f3e0682efe4e25808249d8fcb55927f6a9f446b8dc1d0a2c3b8cb133a5673b59a6d55ce754ec0c9a555401',
          ),
        ]),
        'X448',
        true,
        ['deriveBits'],
      )
      // @ts-expect-error getPublicKey is not in TypeScript's WebCrypto definitions yet.
      const publicKey = await crypto.subtle.getPublicKey(privateKey, [])
      const actual = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey))
      const expected = Uint8Array.fromHex(
        '145d083ea7a6379dbb32dcbd8aff4c206ea5d069b75e96c6dd2a3e38f441471ac97adca641fdad66685a96f32b7c3e064635fab3cc89234e',
      )

      assert.notDeepStrictEqual(
        actual,
        expected,
        'Deno native X448 now matches HPKE vectors; remove the Deno X448 exception and update README.md',
      )
    },
  )
})
