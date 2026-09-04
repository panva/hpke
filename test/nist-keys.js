// Reference public points calculated independently with @noble/curves.
// Covers small scalars, leading zeros, both y parities, and order - 1.
export const nistFixtures = [
  {
    kem: 'KEM_DHKEM_P256_HKDF_SHA256',
    order: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    keys: [
      {
        privateKey: '0000000000000000000000000000000000000000000000000000000000000001',
        publicKey:
          '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
      },
      {
        privateKey: '0000000000000000000000000000000000000000000000000000000000000002',
        publicKey:
          '047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1',
      },
      {
        privateKey: '0000000000000000000000000000000000000000000000000000000000000003',
        publicKey:
          '045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032',
      },
      {
        privateKey: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550',
        publicKey:
          '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a',
      },
    ],
  },
  {
    kem: 'KEM_DHKEM_P384_HKDF_SHA384',
    order:
      'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    keys: [
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
        publicKey:
          '04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
      },
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002',
        publicKey:
          '0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80',
      },
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003',
        publicKey:
          '04077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831c995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1',
      },
      {
        privateKey:
          'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972',
        publicKey:
          '04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0',
      },
    ],
  },
  {
    kem: 'KEM_DHKEM_P521_HKDF_SHA512',
    order:
      '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    keys: [
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
        publicKey:
          '0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
      },
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002',
        publicKey:
          '0400433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02',
      },
      {
        privateKey:
          '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003',
        publicKey:
          '0401a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37ad7d013e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1ee86c0e5',
      },
      {
        privateKey:
          '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408',
        publicKey:
          '0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd6600e7c6d6958765c43ffba375a04bd382e426670abbb6a864bb97e85042e8d8c199d368118d66a10bd9bf3aaf46fec052f89ecac38f795d8d3dbf77416b89602e99af',
      },
    ],
  },
]

const fromHex = (hex) => Uint8Array.from(hex.match(/../g), (byte) => parseInt(byte, 16))
const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
const fromBase64Url = (value) =>
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (char) =>
    char.charCodeAt(0),
  )

export async function checkNistKeys(HPKE) {
  let checked = 0
  for (const fixture of nistFixtures) {
    const suite = new HPKE.CipherSuite(
      HPKE[fixture.kem],
      HPKE.KDF_HKDF_SHA256,
      HPKE.AEAD_AES_128_GCM,
    )
    for (const vector of fixture.keys) {
      const scalar = fromHex(vector.privateKey)
      const importing = suite.DeserializePrivateKey(scalar, true)
      scalar.fill(0)
      const privateKey = await importing
      const jwk = await crypto.subtle.exportKey('jwk', privateKey)
      const point = '04' + toHex(fromBase64Url(jwk.x)) + toHex(fromBase64Url(jwk.y))
      if (point !== vector.publicKey || toHex(fromBase64Url(jwk.d)) !== vector.privateKey) {
        throw new Error(`${fixture.kem}: recovered key does not match reference`)
      }
      if (toHex(await suite.SerializePrivateKey(privateKey)) !== vector.privateKey) {
        throw new Error(`${fixture.kem}: private key serialization changed the scalar`)
      }
      const nonExtractable = await suite.DeserializePrivateKey(fromHex(vector.privateKey))
      if (nonExtractable.extractable || nonExtractable.usages.join() !== 'deriveBits') {
        throw new Error(`${fixture.kem}: incorrect final key permissions`)
      }
      const publicKey = await suite.DeserializePublicKey(fromHex(vector.publicKey))
      const plaintext = Uint8Array.of(1, 2, 3)
      const { encapsulatedSecret, ciphertext } = await suite.Seal(publicKey, plaintext)
      const opened = await suite.Open(
        { privateKey: nonExtractable, publicKey },
        encapsulatedSecret,
        ciphertext,
      )
      if (toHex(opened) !== toHex(plaintext)) {
        throw new Error(`${fixture.kem}: non-extractable key cannot decrypt`)
      }
      checked++
    }
    for (const scalar of [
      new Uint8Array(suite.KEM.Nsk),
      fromHex(fixture.order),
      new Uint8Array(suite.KEM.Nsk).fill(0xff),
    ]) {
      try {
        await suite.DeserializePrivateKey(scalar)
      } catch (error) {
        if (error instanceof HPKE.DeserializeError && error.cause?.message === 'Invalid scalar')
          continue
        throw error
      }
      throw new Error(`${fixture.kem}: accepted out-of-range scalar`)
    }
  }
  return checked
}
