














































































































class SenderContext {
  #suite        
  #key            
  #base_nonce            
  #exporter_secret            
  #mode                                    
  #seq         = 0
  #mutex        

  constructor(
    suite        ,
    mode                                    ,
    key            ,
    base_nonce            ,
    exporter_secret            ,
  ) {
    this.#suite = suite
    this.#mode = mode
    this.#key = key
    this.#base_nonce = base_nonce
    this.#exporter_secret = exporter_secret
  }






  get mode()         {
    return this.#mode
  }






  get seq()         {
    return this.#seq
  }



























  async Seal(plaintext            , aad             )                      {
    checkUint8Array(plaintext, 'plaintext')
    aad ??= new Uint8Array()
    checkUint8Array(aad, 'aad')
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }

    this.#mutex ??= new Mutex()
    const release = await this.#mutex.lock()
    let ct            
    try {
      ct = await this.#suite.AEAD.Seal(
        this.#key,
        ComputeNonce(this.#base_nonce, this.#seq, this.#suite.AEAD.Nn),
        aad,
        plaintext,
      )
      this.#seq = IncrementSeq(this.#seq)
      return ct
    } finally {
      release()
    }
  }
























  async Export(exporterContext            , length        )                      {
    return await ContextExport(this.#suite, this.#exporter_secret, exporterContext, length)
  }





  get Nt()         {
    return this.#suite.AEAD.Nt
  }
}





















class RecipientContext {
  #suite        
  #key            
  #base_nonce            
  #exporter_secret            
  #mode                                    
  #seq         = 0
  #mutex        

  constructor(
    suite        ,
    mode                                    ,
    key            ,
    base_nonce            ,
    exporter_secret            ,
  ) {
    this.#suite = suite
    this.#mode = mode
    this.#key = key
    this.#base_nonce = base_nonce
    this.#exporter_secret = exporter_secret
  }






  get mode()         {
    return this.#mode
  }






  get seq()         {
    return this.#seq
  }




























  async Open(ciphertext            , aad             )                      {
    checkUint8Array(ciphertext, 'ciphertext')
    aad ??= new Uint8Array()
    checkUint8Array(aad, 'aad')

    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }

    this.#mutex ??= new Mutex()
    const release = await this.#mutex.lock()
    try {
      let pt            
      try {
        pt = await this.#suite.AEAD.Open(
          this.#key,
          ComputeNonce(this.#base_nonce, this.#seq, this.#suite.AEAD.Nn),
          aad,
          ciphertext,
        )
      } catch (cause) {
        if (cause instanceof MessageLimitReachedError || cause instanceof NotSupportedError) {
          throw cause
        }

        throw new OpenError('AEAD decryption failed', { cause })
      }
      this.#seq = IncrementSeq(this.#seq)
      return pt
    } finally {
      release()
    }
  }
























  async Export(exporterContext            , length        )                      {
    return await ContextExport(this.#suite, this.#exporter_secret, exporterContext, length)
  }
}






const validate =                             (factory         , type        )    => {
  try {
    const result = factory()
    if (result.type !== type) {
      throw new Error(`Invalid "${type}" return discriminator`)
    }
    return result
  } catch (cause) {
    throw new TypeError(`Invalid "${type}"`, { cause })
  }
}
























export class CipherSuite {
  #suite        






























































  constructor(KEM            , KDF            , AEAD             ) {
    const kem = validate(KEM, 'KEM')
    const kdf = validate(KDF, 'KDF')
    const aead = validate(AEAD, 'AEAD')

    this.#suite = {
      KEM: kem,
      KDF: kdf,
      AEAD: aead,
      id: concat(encode('HPKE'), I2OSP(kem.id, 2), I2OSP(kdf.id, 2), I2OSP(aead.id, 2)),
    }
  }






  get KEM()   












    {
    return {
      id: this.#suite.KEM.id,
      name: this.#suite.KEM.name,
      Nsecret: this.#suite.KEM.Nsecret,
      Nenc: this.#suite.KEM.Nenc,
      Npk: this.#suite.KEM.Npk,
      Nsk: this.#suite.KEM.Nsk,
    }
  }






  get KDF()   
















    {
    return {
      id: this.#suite.KDF.id,
      name: this.#suite.KDF.name,
      stages: this.#suite.KDF.stages,
      Nh: this.#suite.KDF.Nh,
    }
  }







  get AEAD()   










    {
    return {
      id: this.#suite.AEAD.id,
      name: this.#suite.AEAD.name,
      Nk: this.#suite.AEAD.Nk,
      Nn: this.#suite.AEAD.Nn,
      Nt: this.#suite.AEAD.Nt,
    }
  }


















  async GenerateKeyPair(extractable          )                   {
    extractable ??= false
    checkExtractable(extractable)
    return await this.#suite.KEM.GenerateKeyPair(extractable)
  }




























  async DeriveKeyPair(ikm            , extractable          )                   {
    extractable ??= false
    checkExtractable(extractable)
    checkUint8Array(ikm, 'ikm')
    if (ikm.byteLength < this.#suite.KEM.Nsk) {
      throw new DeriveKeyPairError('Insufficient "ikm" length')
    }
    try {
      return await this.#suite.KEM.DeriveKeyPair(ikm, extractable)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeriveKeyPairError('Key derivation failed', { cause })
    }
  }

















  async SerializePrivateKey(privateKey     )                      {
    isKey(privateKey, 'private', true)

    return await this.#suite.KEM.SerializePrivateKey(privateKey)
  }

















  async SerializePublicKey(publicKey     )                      {
    isKey(publicKey, 'public', true)

    return await this.#suite.KEM.SerializePublicKey(publicKey)
  }




















  async DeserializePrivateKey(privateKey            , extractable          )               {
    extractable ??= false
    checkExtractable(extractable)
    checkUint8Array(privateKey, 'privateKey')

    try {
      if (privateKey.byteLength !== this.#suite.KEM.Nsk) {
        throw new Error('Invalid "privateKey" length')
      }
      return await this.#suite.KEM.DeserializePrivateKey(privateKey, extractable)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Private key deserialization failed', { cause })
    }
  }


















  async DeserializePublicKey(publicKey            )               {
    checkUint8Array(publicKey, 'publicKey')

    try {
      if (publicKey.byteLength !== this.#suite.KEM.Npk) {
        throw new Error('Invalid "publicKey" length')
      }
      return await this.#suite.KEM.DeserializePublicKey(publicKey)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Public key deserialization failed', { cause })
    }
  }



































  async Seal(
    publicKey     ,
    plaintext            ,
    options                                                                                ,
  )                                                                      {
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }
    const { encapsulatedSecret, ctx } = await this.SetupSender(publicKey, options)
    const ciphertext = await ctx.Seal(plaintext, options?.aad)
    return { encapsulatedSecret, ciphertext }
  }





































  async Open(
    privateKey               ,
    encapsulatedSecret            ,
    ciphertext            ,
    options                                                                                ,
  )                      {
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }
    const ctx = await this.SetupRecipient(privateKey, encapsulatedSecret, options)
    return await ctx.Open(ciphertext, options?.aad)
  }




































  async SendExport(
    publicKey     ,
    exporterContext            ,
    length        ,
    options                                                              ,
  )                                                                          {
    const { encapsulatedSecret, ctx } = await this.SetupSender(publicKey, options)
    const exportedSecret = await ctx.Export(exporterContext, length)
    return { encapsulatedSecret, exportedSecret }
  }






































  async ReceiveExport(
    privateKey               ,
    encapsulatedSecret            ,
    exporterContext            ,
    length        ,
    options                                                              ,
  )                      {
    const ctx = await this.SetupRecipient(privateKey, encapsulatedSecret, options)
    return await ctx.Export(exporterContext, length)
  }












































  async SetupSender(
    publicKey     ,
    options                                                              ,
  )                                                                  {
    isKey(publicKey, 'public')

    let shared_secret            
    let enc            
    try {
      const result = await this.#suite.KEM.Encap(publicKey)
      shared_secret = result.shared_secret
      enc = result.enc
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new EncapError('Encapsulation failed', { cause })
    }

    const mode = options?.psk?.byteLength ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.pskId,
    )

    const ctx = new SenderContext(this.#suite, mode, key, base_nonce, exporter_secret)
    return { encapsulatedSecret: enc, ctx }
  }

















































  async SetupRecipient(
    privateKey               ,
    encapsulatedSecret            ,
    options                                                              ,
  )                            {
    const { skR, pkR } = this.#extractRecipientKeys(privateKey)
    checkUint8Array(encapsulatedSecret, 'encapsulatedSecret')
    if (encapsulatedSecret.byteLength !== this.#suite.KEM.Nenc) {
      throw new DecapError('Invalid encapsulated secret length')
    }

    let shared_secret            
    try {
      shared_secret = await this.#suite.KEM.Decap(encapsulatedSecret, skR, pkR)
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DecapError('Decapsulation failed', { cause })
    }

    const mode = options?.psk?.byteLength ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.pskId,
    )

    return new RecipientContext(this.#suite, mode, key, base_nonce, exporter_secret)
  }

  #extractRecipientKeys(skR               )                                     {
    if (isKeyPair(skR)) {
      return { skR: skR.privateKey, pkR: skR.publicKey }
    }

    isKey(skR, 'private')
    return { skR, pkR: undefined }
  }
}











export class ValidationError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'ValidationError'

    Error.captureStackTrace?.(this, ValidationError)
  }
}







export class DeserializeError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DeserializeError'

    Error.captureStackTrace?.(this, DeserializeError)
  }
}







export class EncapError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'EncapError'

    Error.captureStackTrace?.(this, EncapError)
  }
}







export class DecapError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DecapError'

    Error.captureStackTrace?.(this, DecapError)
  }
}







export class OpenError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'OpenError'

    Error.captureStackTrace?.(this, OpenError)
  }
}







export class MessageLimitReachedError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'MessageLimitReachedError'

    Error.captureStackTrace?.(this, MessageLimitReachedError)
  }
}







export class DeriveKeyPairError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DeriveKeyPairError'

    Error.captureStackTrace?.(this, DeriveKeyPairError)
  }
}







export class NotSupportedError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'NotSupportedError'

    Error.captureStackTrace?.(this, NotSupportedError)
  }
}




















export const MODE_BASE = 0x00










export const MODE_PSK = 0x01





































































































































export function concat(...buffers              )             {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  for (const buffer of buffers) {
    buf.set(buffer, i)
    i += buffer.length
  }
  return buf
}

function slice(buffer            , start         , end         ) {
  return Uint8Array.prototype.slice.call(buffer, start, end)
}












export function encode(string        )             {
  const bytes = new Uint8Array(string.length)
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i)
    if (code > 0x7f) {
      throw new TypeError('Input string must contain only ASCII characters')
    }
    bytes[i] = code
  }
  return bytes
}

function xor(a            , b            )             {
  if (a.byteLength !== b.byteLength) {
    throw new Error('XOR operands must have equal length')
  }
  const buf = new Uint8Array(a.byteLength)
  for (let i = 0; i < a.byteLength; i++) {
    buf[i] = a[i]  ^ b[i] 
  }
  return buf
}

function lengthPrefixed(x            )             {
  return concat(I2OSP(x.byteLength, 2), x)
}
























export async function LabeledDerive(
  KDF                     ,
  suite_id            ,
  ikm            ,
  label            ,
  context            ,
  L        ,
)                      {
  const labeled_ikm = concat(
    ikm,
    encode('HPKE-v1'),
    suite_id,
    lengthPrefixed(label),
    I2OSP(L, 2),
    context,
  )
  return await KDF.Derive(labeled_ikm, L)
}













































































































































































































































































export async function LabeledExtract(
  KDF                      ,
  suite_id            ,
  salt            ,
  label            ,
  ikm            ,
)                      {
  const labeled_ikm = concat(encode('HPKE-v1'), suite_id, label, ikm)
  return await KDF.Extract(salt, labeled_ikm)
}




















export async function LabeledExpand(
  KDF                     ,
  suite_id            ,
  prk            ,
  label            ,
  info            ,
  L        ,
)                      {
  const labeled_info = concat(I2OSP(L, 2), encode('HPKE-v1'), suite_id, label, info)
  return await KDF.Expand(prk, labeled_info, L)
}













































































































































































































function isKeyPair(skR         )                 {
  if (!skR || typeof skR !== 'object') return false
  if ('publicKey' in skR && 'privateKey' in skR) {
    const pkR = skR.publicKey
    skR = skR.privateKey
    try {
      isKey(pkR, 'public')
      isKey(skR, 'private')
      if (pkR.algorithm.name !== skR.algorithm.name) {
        throw new TypeError('key pair algorithms do not match')
      }
    } catch (cause) {
      throw new TypeError('Invalid "privateKey"', { cause })
    }
    return true
  }
  return false
}

function isKey(key         , type        , extractable          )                     {
  const k = key       
  if (
    typeof k.algorithm !== 'object' ||
    typeof k.algorithm.name !== 'string' ||
    typeof k.extractable !== 'boolean' ||
    typeof k.type !== 'string' ||
    k.type !== type
  ) {
    throw new TypeError(`Invalid "${type}Key"`)
  }

  if (extractable && k.extractable !== true) {
    throw new TypeError(`"${type}Key" must be extractable`)
  }
}
























































































































export function I2OSP(n        , w        )             {
  if (!Number.isSafeInteger(w) || w <= 0) {
    throw new Error('w must be a positive safe integer')
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error('n must be a non-negative safe integer')
  }
  const max = Math.pow(256, w)
  if (n >= max) {
    throw new Error('n too large to fit in w-length byte string')
  }
  const ret = new Uint8Array(w)
  let num = n
  for (let i = 0; i < w && num; i++) {
    ret[w - (i + 1)] = num % 256
    num = Math.floor(num / 256)
  }
  return ret
}

function KDFStages(KDF     )        {
  if (KDF.stages === 1 || KDF.stages === 2) {
    return KDF.stages
  }

  throw new Error('unreachable')
}







































const NotApplicable = () => {
  throw new Error('unreachable')
}

const EXPORT_ONLY = 0xffff












export const AEAD_EXPORT_ONLY              = function ()       {
  return {
    id: EXPORT_ONLY,
    type: 'AEAD',
    name: 'Export-only',
    Nk: 0,
    Nn: 0,
    Nt: 0,
    Seal: NotApplicable,
    Open: NotApplicable,
  }
}





async function subtle   (promise                                      , name        )             {
  try {
    return await promise(crypto.subtle)
  } catch (cause) {
    if (
      cause instanceof TypeError ||
      (cause instanceof DOMException && cause.name === 'NotSupportedError')
    ) {
      throw new NotSupportedError(`${name} is unsupported in this runtime`, { cause })
    }
    throw cause
  }
}







function sab(input                 )                             {
  return typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer
}

function ab(input            )              {
  if (sab(input.buffer)) {
    throw new TypeError('input must not be a SharedArrayBuffer')
  }
  if (input.byteLength === input.buffer.byteLength) {
    return input.buffer
  }
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
}

function HKDF_SHARED()           {
  return {
    stages: 2,
    Derive: NotApplicable,
    async Extract(            _salt, _ikm) {
      let salt             
      if (_salt.byteLength === 0) {
        salt = new ArrayBuffer(this.Nh)
      } else {
        salt = ab(_salt)
      }
      const ikm = ab(_ikm)
      return new Uint8Array(
        await subtle(
          async (c) =>
            c.sign(
              'HMAC',
              await c.importKey('raw', salt, { name: 'HMAC', hash: this.hash }, false, ['sign']),
              ikm,
            ),
          this.name,
        ),
      )
    },
    async Expand(            _prk, info, L) {
      if (_prk.byteLength < this.Nh) {
        throw new Error('prk.byteLength < this.Nh')
      }
      if (L > 255 * this.Nh) {
        throw new Error('L must be <= 255*Nh')
      }
      const N = Math.ceil(L / this.Nh)
      const prk = ab(_prk)
      const key = await subtle(
        (c) => c.importKey('raw', prk, { name: 'HMAC', hash: this.hash }, false, ['sign']),
        this.name,
      )

      const T = new Uint8Array(N * this.Nh)
      let T_prev = new Uint8Array()

      for (let i = 0; i < N; i++) {
        const input = new Uint8Array(T_prev.byteLength + info.byteLength + 1)
        input.set(T_prev)
        input.set(info, T_prev.byteLength)
        input[T_prev.byteLength + info.byteLength] = i + 1

        const T_i = new Uint8Array(await subtle((c) => c.sign('HMAC', key, input), this.name))

        T.set(T_i, i * this.Nh)
        T_prev = T_i
      }

      return slice(T, 0, L)
    },
  }
}
























export const KDF_HKDF_SHA256             = function ()       {
  return { id: 0x0001, type: 'KDF', name: 'HKDF-SHA256', Nh: 32, hash: 'SHA-256', ...HKDF_SHARED() }
}




















export const KDF_HKDF_SHA384             = function ()       {
  return { id: 0x0002, type: 'KDF', name: 'HKDF-SHA384', Nh: 48, hash: 'SHA-384', ...HKDF_SHARED() }
}




















export const KDF_HKDF_SHA512             = function ()       {
  return { id: 0x0003, type: 'KDF', name: 'HKDF-SHA512', Nh: 64, hash: 'SHA-512', ...HKDF_SHARED() }
}









async function ShakeDerive(name        , variant        , ikm             , L        ) {
  const bits = L << 3
  const alg = { name: variant, length: bits, outputLength: bits }
  return new Uint8Array(await subtle((c) => c.digest(alg, ikm), name))
}

function SHAKE_SHARED()           {
  return {
    stages: 1,
    async Derive(             labeled_ikm, L        ) {
      return await ShakeDerive(this.name, this.algorithm, ab(labeled_ikm), L)
    },
    Extract: NotApplicable,
    Expand: NotApplicable,
  }
}




















export const KDF_SHAKE128             = function ()        {
  return {
    id: 0x0010,
    type: 'KDF',
    name: 'SHAKE128',
    Nh: 32,
    algorithm: 'cSHAKE128',
    ...SHAKE_SHARED(),
  }
}




















export const KDF_SHAKE256             = function ()        {
  return {
    id: 0x0011,
    type: 'KDF',
    name: 'SHAKE256',
    Nh: 64,
    algorithm: 'cSHAKE256',
    ...SHAKE_SHARED(),
  }
}

async function getPublicKeyByExport(
  name        ,
  key           ,
  usages            ,
)                     {
  if (!key.extractable) {
    throw new TypeError(
      '"privateKey" must be extractable or a Key Pair must be used in this runtime',
    )
  }

  return await subtle(async (c) => {
    const jwk = await c.exportKey('jwk', key)
    return c.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }              ,
      key.algorithm,
      true,
      usages,
    )
  }, name)
}

async function getPublicKey(name        , key           , usages            )                     {
  return (

    ((await subtle((c) => c.getPublicKey?.(key, usages), name))             ) ||
    (await getPublicKeyByExport(name, key, usages))
  )
}


function checkNotAllZeros(buffer            )       {
  let or = 0
  for (let i = 0; i < buffer.length; i++) {
    or |= buffer[i] 
  }
  if (or === 0) {
    throw new ValidationError('DH shared secret is an all-zero value')
  }
}




















function fromBase64(input        ) {
  input = input.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(input)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toBase64Url(bytes            )         {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] )
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function toB64u(input            ) {

  return input.toBase64?.({ alphabet: 'base64url', omitPadding: true }) || toBase64Url(input)
}

function b64u(input        )             {

  return Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fromBase64(input)
}














































































































































































































































































































































































































































































export const KEM_DHKEM_P256_HKDF_SHA256             = function ()                          {
  const id = 0x0010
  const name = 'DHKEM(P-256, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 32,
    Nenc: 65,
    Ndh: 32,
    ...P256,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

const P384                  = {
  algorithm: { name: 'ECDH', namedCurve: 'P-384' },
  Npk: 97,
  Nsk: 48,
  order:
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
  bitmask: 0xff,
  prime:
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  Gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  Gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
}





















export const KEM_DHKEM_P384_HKDF_SHA384             = function ()                          {
  const id = 0x0011
  const name = 'DHKEM(P-384, HKDF-SHA384)'
  const kdf = KDF_HKDF_SHA384()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 48,
    Nenc: 97,
    Ndh: 48,
    ...P384,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

const P521                  = {
  Npk: 133,
  Nsk: 66,
  algorithm: { name: 'ECDH', namedCurve: 'P-521' },
  order:
    0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
  bitmask: 0x01,
  prime:
    0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  Gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
  Gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
}





















export const KEM_DHKEM_P521_HKDF_SHA512             = function ()                          {
  const id = 0x0012
  const name = 'DHKEM(P-521, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 64,
    Nenc: 133,
    Ndh: 66,
    ...P521,
    DeriveKeyPair: DeriveKeyPairNist,
    DeserializePrivateKey: DeserializePrivateKeyNist,
    ...DHKEM_SHARED(),
  }
}

























export const KEM_DHKEM_X25519_HKDF_SHA256             = function ()                                {
  const id = 0x0020
  const name = 'DHKEM(X25519, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 32,
    Nenc: 32,
    Npk: 32,
    Nsk: 32,
    Ndh: 32,
    algorithm: { name: 'X25519' },
    pkcs8: Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20),
    DeriveKeyPair: DeriveKeyPairX,
    async DeserializePrivateKey(key, extractable) {
      return await CurveKeyFromD(name, this.Nsk, this.pkcs8, this.algorithm, key, extractable)
    },
    ...DHKEM_SHARED(),
  }
}





















export const KEM_DHKEM_X448_HKDF_SHA512             = function ()                                {
  const id = 0x0021
  const name = 'DHKEM(X448, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    kdf,
    Nsecret: 64,
    Nenc: 56,
    Npk: 56,
    Nsk: 56,
    Ndh: 56,
    algorithm: { name: 'X448' },
    pkcs8: Uint8Array.of(0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38),
    DeriveKeyPair: DeriveKeyPairX,
    async DeserializePrivateKey(key, extractable) {
      return await CurveKeyFromD(name, this.Nsk, this.pkcs8, this.algorithm, key, extractable)
    },
    ...DHKEM_SHARED(),
  }
}











function MLKEM_SHARED()           {
  return {
    async DeriveKeyPair(             ikm, extractable) {
      const dk = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        this.Nsk,
      )

      const privateKey = (await this.DeserializePrivateKey(dk, extractable))             

      const usages             = ['encapsulateBits']
      const publicKey = await getPublicKey(this.name, privateKey, usages)

      return { privateKey, publicKey }
    },
    async GenerateKeyPair(             extractable) {

      const usages             = ['encapsulateBits', 'decapsulateBits']
      return (await subtle(
        (c) => c.generateKey(this.algorithm, extractable, usages),
        this.name,
      ))                 
    },
    async SerializePublicKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)

      const format                            = 'raw-public'
      return new Uint8Array(await subtle((c) => c.exportKey(format, key), this.name))
    },
    async DeserializePublicKey(             _key) {

      const format                            = 'raw-public'

      const usages             = ['encapsulateBits']
      const key = ab(_key)
      return await subtle((c) => c.importKey(format, key, this.algorithm, true, usages), this.name)
    },
    async SerializePrivateKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)

      const format                            = 'raw-seed'
      return new Uint8Array(await subtle((c) => c.exportKey(format, key), this.name))
    },
    async DeserializePrivateKey(             _key, extractable) {

      const format                            = 'raw-seed'

      const usages             = ['decapsulateBits']
      const key = ab(_key)
      return await subtle(
        (c) => c.importKey(format, key, this.algorithm, extractable, usages),
        this.name,
      )
    },
    async Encap(             pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)

      const { sharedKey, ciphertext } = (await subtle(

        (c) => c.encapsulateBits(this.algorithm, pkR),
        this.name,
      ))                                                       

      return { shared_secret: new Uint8Array(sharedKey), enc: new Uint8Array(ciphertext) }
    },
    async Decap(             _enc, skR, _pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      const enc = ab(_enc)
      return new Uint8Array(
        await subtle(

          (c) => c.decapsulateBits(this.algorithm, skR, enc),
          this.name,
        ),
      )
    },
  }
}
























export const KEM_ML_KEM_512             = function ()        {
  const id = 0x0040
  const name = 'ML-KEM-512'
  const kdf = KDF_SHAKE256()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 768,
    Npk: 800,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-512' },
    kdf,
    ...MLKEM_SHARED(),
  }
}




















export const KEM_ML_KEM_768             = function ()        {
  const id = 0x0041
  const name = 'ML-KEM-768'
  const kdf = KDF_SHAKE256()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1088,
    Npk: 1184,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-768' },
    kdf,
    ...MLKEM_SHARED(),
  }
}




















export const KEM_ML_KEM_1024             = function ()        {
  const id = 0x0042
  const name = 'ML-KEM-1024'
  const kdf = KDF_SHAKE256()

  kdf.name = name
  return {
    id,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1568,
    Npk: 1568,
    Nsk: 64,
    algorithm: { name: 'ML-KEM-1024' },
    kdf,
    ...MLKEM_SHARED(),
  }
}








function AEAD_SHARED()            {
  return {
    async Seal(                     _key, _nonce, _aad, _pt) {
      const nonce = ab(_nonce)
      const aad = ab(_aad)
      const key = ab(_key)
      const pt = ab(_pt)
      return new Uint8Array(
        await subtle(
          async (c) =>
            c.encrypt(
              { name: this.algorithm, iv: nonce, additionalData: aad },
              await c.importKey(this.keyFormat, key, this.algorithm, false, ['encrypt']),
              pt,
            ),
          this.name,
        ),
      )
    },
    async Open(                     _key, _nonce, _aad, _ct) {
      const nonce = ab(_nonce)
      const aad = ab(_aad)
      const key = ab(_key)
      const ct = ab(_ct)
      return new Uint8Array(
        await subtle(
          async (c) =>
            c.decrypt(
              { name: this.algorithm, iv: nonce, additionalData: aad },
              await c.importKey(this.keyFormat, key, this.algorithm, false, ['decrypt']),
              ct,
            ),
          this.name,
        ),
      )
    },
  }
}























export const AEAD_AES_128_GCM              = function ()                {
  return {
    id: 0x0001,
    type: 'AEAD',
    name: 'AES-128-GCM',
    Nk: 16,
    Nn: 12,
    Nt: 16,
    algorithm: 'AES-GCM',
    keyFormat: 'raw',
    ...AEAD_SHARED(),
  }
}



















export const AEAD_AES_256_GCM              = function ()                {
  return {
    id: 0x0002,
    type: 'AEAD',
    name: 'AES-256-GCM',
    Nk: 32,
    Nn: 12,
    Nt: 16,
    algorithm: 'AES-GCM',
    keyFormat: 'raw',
    ...AEAD_SHARED(),
  }
}



















export const AEAD_ChaCha20Poly1305              = function AEAD_ChaCha20Poly1305()                {
  return {
    id: 0x0003,
    type: 'AEAD',
    name: 'ChaCha20Poly1305',
    Nk: 32,
    Nn: 12,
    Nt: 16,
    algorithm: 'ChaCha20-Poly1305',

    keyFormat: 'raw-secret',
    ...AEAD_SHARED(),
  }
}






const InvalidInvocation = (_             ) => {
  if (_ !== priv) {
    throw new Error('invalid invocation')
  }
}
const priv = Symbol()
class HybridKey                {
  #algorithm              
  #type                      
  #extractable         
  #t           
  #pq           
  #seed                         
  #publicKey                        

  static #isValid(key           )          {
    return key.#algorithm !== undefined
  }

  static validate(key         , extractable          )                           {
    try {
      if (!HybridKey.#isValid(key             )) {
        throw new TypeError('unexpected key constructor')
      }
    } catch {
      throw new TypeError('unexpected key constructor')
    }
    if (extractable && !(key             ).extractable) {
      throw new TypeError('key must be extractable')
    }
  }

  constructor(
    _             ,
    algorithm              ,
    type                      ,
    extractable         ,
    pq           ,
    t           ,
    seed             ,
    publicKey            ,
  ) {
    InvalidInvocation(_)
    this.#algorithm = algorithm
    this.#type = type
    this.#extractable = extractable
    this.#pq = pq
    this.#t = t
    this.#seed = seed
    this.#publicKey = publicKey
  }

  get algorithm() {
    return { name: this.#algorithm.name }
  }

  get extractable() {
    return this.#extractable
  }

  get type() {
    return this.#type
  }

  getPublicKey(_             ) {
    InvalidInvocation(_)
    return this.#publicKey
  }

  getSeed(_             ) {
    InvalidInvocation(_)
    return slice(this.#seed )
  }

  getT(_             ) {
    InvalidInvocation(_)
    return this.#t
  }

  getPq(_             ) {
    InvalidInvocation(_)
    return this.#pq
  }
}

function split(N1        , N2        , x            )                           {
  if (x.byteLength !== N1 + N2) {
    throw new Error('x.byteLength !== N1 + N2')
  }

  const x1 = slice(x, 0, N1)
  const x2 = slice(x, -N2)

  return [x1, x2]
}

function RandomScalarNist(t                , seed            )             {
  let sk_bigint = 0n
  let start = 0
  let end = t.Nscalar 
  sk_bigint = OS2IP(slice(seed, start, end))

  while (sk_bigint === 0n || sk_bigint >= t.order ) {
    start = end
    end = end + t.Nscalar 
    if (end > seed.byteLength) {
      throw new DeriveKeyPairError('Rejection sampling failed')
    }
    sk_bigint = OS2IP(slice(seed, start, end))
  }
  return bigIntToUint8Array(sk_bigint, t.Nscalar )
}


















































































































































































































































































export const KEM_MLKEM768_X25519             = function ()            {
  const id = 0x647a
  const name = 'MLKEM768-X25519'
  const kdf = KDF_SHAKE256()
  const pkcs8 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);

  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1120,
    Npk: 1216,
    Nsk: 32,
    algorithm: { name: 'MLKEM768-X25519' },
    pq: { algorithm: { name: 'ML-KEM-768' }, Nseed: 64, Npk: 1184, Nct: 1088 },
    t: {
      algorithm: { name: 'X25519' },
      Nseed: 32,
      Npk: 32,
      Nss: 32,
      Nsk: 32,
      Nct: 32,
      async GetKeyPair(sk) {
        const privateKey = await CurveKeyFromD(name, this.Nsk, pkcs8, this.algorithm, sk, true)
        const publicKey = await getPublicKey(name, privateKey, [])

        return { privateKey, publicKey }
      },
    },
    label: Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c),
    ...PQTKEM_SHARED(),
  }
}




















export const KEM_MLKEM768_P256             = function ()            {
  const id = 0x0050
  const name = 'MLKEM768-P256'
  const kdf = KDF_SHAKE256()

  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1153,
    Npk: 1249,
    Nsk: 32,
    algorithm: { name: 'MLKEM768-P256' },
    pq: { algorithm: { name: 'ML-KEM-768' }, Nseed: 64, Npk: 1184, Nct: 1088 },
    t: {
      ...P256,
      Nseed: 128,
      Nss: 32,
      Nct: 65,
      Nscalar: 32,
      order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
      },
      GetKeyPair(sk) {
        return GetKeyPairNist(P256, sk, true, name)
      },
    },
    label: Uint8Array.of(0x4d, 0x4c, 0x4b, 0x45, 0x4d, 0x37, 0x36, 0x38, 0x2d, 0x50, 0x32, 0x35, 0x36),
    ...PQTKEM_SHARED(),
  }
}




















export const KEM_MLKEM1024_P384             = function ()            {
  const id = 0x0051
  const name = 'MLKEM1024-P384'
  const kdf = KDF_SHAKE256()

  kdf.name = name
  return {
    id,
    kdf,
    suite_id: concat(encode('KEM'), I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret: 32,
    Nenc: 1665,
    Npk: 1665,
    Nsk: 32,
    algorithm: { name: 'MLKEM1024-P384' },
    pq: { algorithm: { name: 'ML-KEM-1024' }, Nseed: 64, Npk: 1568, Nct: 1568 },
    t: {
      ...P384,
      Nseed: 48,
      Nss: 48,
      Nct: 97,
      Nscalar: 48,
      order:
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
      },
      GetKeyPair(sk) {
        return GetKeyPairNist(P384, sk, true, name)
      },
    },
    label: Uint8Array.of(0x4d, 0x4c, 0x4b, 0x45, 0x4d, 0x31, 0x30, 0x32, 0x34, 0x2d, 0x50, 0x33, 0x38, 0x34),
    ...PQTKEM_SHARED(),
  }
}
