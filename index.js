














































function ComputeNonce(base_nonce            , seq        , Nn        )             {
  const seq_bytes = I2OSP(seq, Nn)
  return xor(base_nonce, seq_bytes)
}

function IncrementSeq(seq        )         {



  if (seq >= Number.MAX_SAFE_INTEGER) {
    throw new MessageLimitReachedError('Sequence number overflow')
  }
  return ++seq
}

async function ContextExport(
  suite        ,
  exporter_secret            ,
  exporter_context            ,
  L        ,
) {

  if (suite.KDF.stages !== 1 && suite.KDF.stages !== 2) {
    throw new Error('unreachable')
  }
  if (!(exporter_context instanceof Uint8Array)) {
    throw new TypeError('"exporter_context" must be a Uint8Array')
  }
  if (!Number.isInteger(L) || L <= 0 || L > 0xffff) {
    throw new TypeError('"L" must be a positive integer not exceeding 65535')
  }
  const Export = suite.KDF.stages === 1 ? ExportOneStage : ExportTwoStage
  return await Export(suite.KDF, suite.id, exporter_secret, exporter_context, L)
}

class Mutex {
  #locked                = Promise.resolve()

  async lock()                      {
    let releaseLock             
    const nextLock = new Promise      ((resolve) => {
      releaseLock = resolve
    })
    const previousLock = this.#locked
    this.#locked = nextLock
    await previousLock
    return releaseLock
  }
}




















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
    mode        ,
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
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('"plaintext" must be an Uint8Array')
    }
    aad ??= new Uint8Array()
    if (!(aad instanceof Uint8Array)) {
      throw new TypeError('"aad" must be an Uint8Array')
    }
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























  async Export(exporter_context            , L        )                      {
    return await ContextExport(this.#suite, this.#exporter_secret, exporter_context, L)
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
    mode        ,
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
    if (!(ciphertext instanceof Uint8Array)) {
      throw new TypeError('"ciphertext" must be an Uint8Array')
    }

    aad ??= new Uint8Array()
    if (!(aad instanceof Uint8Array)) {
      throw new TypeError('"aad" must be an Uint8Array')
    }

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























  async Export(exporter_context            , L        )                      {
    return await ContextExport(this.#suite, this.#exporter_secret, exporter_context, L)
  }
}





























export class CipherSuite {
  #suite        






























































  constructor(KEM            , KDF            , AEAD             ) {
    const kem = KEM()
    if (kem.type !== 'KEM') {
      throw new TypeError('provided "KEM" is not a KEM')
    }
    const kdf = KDF()
    if (kdf.type !== 'KDF') {
      throw new TypeError('provided "KDF" is not a KDF')
    }
    const aead = AEAD()
    if (aead.type !== 'AEAD') {
      throw new TypeError('provided "AEAD" is not an AEAD')
    }

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
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }
    return await this.#suite.KEM.GenerateKeyPair(extractable)
  }























  async DeriveKeyPair(ikm            , extractable          )                   {
    extractable ??= false
    if (!(ikm instanceof Uint8Array)) {
      throw new TypeError('"ikm" must be an Uint8Array')
    }
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }
    if (ikm.byteLength < this.KEM.Nsk) {
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

















  async SerializePrivateKey(private_key     )                      {
    isKey(private_key, 'private', true)

    return await this.#suite.KEM.SerializePrivateKey(private_key)
  }

















  async SerializePublicKey(public_key     )                      {
    isKey(public_key, 'public', true)

    return await this.#suite.KEM.SerializePublicKey(public_key)
  }




















  async DeserializePrivateKey(private_key            , extractable          )               {
    extractable ??= false
    if (!(private_key instanceof Uint8Array)) {
      throw new TypeError('"private_key" must be an Uint8Array')
    }
    if (typeof extractable !== 'boolean') {
      throw new TypeError('"extractable" must be a boolean')
    }

    try {
      if (private_key.byteLength !== this.KEM.Nsk) {
        throw new Error('Invalid "private_key" length')
      }
      return await this.#suite.KEM.DeserializePrivateKey(private_key, extractable)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Private key deserialization failed', { cause })
    }
  }


















  async DeserializePublicKey(public_key            )               {
    if (!(public_key instanceof Uint8Array)) {
      throw new TypeError('"public_key" must be an Uint8Array')
    }

    try {
      if (public_key.byteLength !== this.KEM.Npk) {
        throw new Error('Invalid "public_key" length')
      }
      return await this.#suite.KEM.DeserializePublicKey(public_key)
    } catch (cause) {
      if (cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DeserializeError('Public key deserialization failed', { cause })
    }
  }

  #validateEncLength(enc            ) {
    if (enc.byteLength !== this.KEM.Nenc) {
      throw new DecapError('Invalid encapsulated key length')
    }
  }



































  async Seal(
    public_key     ,
    plaintext            ,
    aad             ,
    options    



     ,
  )                                                                    {
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }
    const { encapsulated_key, ctx } = await this.SetupSender(public_key, options)
    const ciphertext = await ctx.Seal(plaintext, aad)
    return { encapsulated_key, ciphertext }
  }










































  async Open(
    private_key               ,
    encapsulated_key            ,
    ciphertext            ,
    aad             ,
    options    



     ,
  )                      {
    this.#validateEncLength(encapsulated_key)
    if (this.#suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }
    const ctx = await this.SetupRecipient(private_key, encapsulated_key, options)
    return await ctx.Open(ciphertext, aad)
  }



































  async SendExport(
    public_key     ,
    exporter_context            ,
    L        ,
    options    



     ,
  )                                                                         {
    const { encapsulated_key, ctx } = await this.SetupSender(public_key, options)
    const exported_secret = await ctx.Export(exporter_context, L)
    return { encapsulated_key, exported_secret }
  }






































  async ReceiveExport(
    private_key               ,
    encapsulated_key            ,
    exporter_context            ,
    L        ,
    options    



     ,
  )                      {
    this.#validateEncLength(encapsulated_key)
    const ctx = await this.SetupRecipient(private_key, encapsulated_key, options)
    return await ctx.Export(exporter_context, L)
  }











































  async SetupSender(
    public_key     ,
    options    



     ,
  )                                                                {
    isKey(public_key, 'public')

    let shared_secret            
    let enc            
    try {
      const result = await this.#suite.KEM.Encap(public_key)
      shared_secret = result.shared_secret
      enc = result.enc
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new EncapError('Encapsulation failed', { cause })
    }

    const mode = options?.psk ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.psk_id,
    )

    const ctx = new SenderContext(this.#suite, mode, key, base_nonce, exporter_secret)
    return { encapsulated_key: enc, ctx }
  }
















































  async SetupRecipient(
    private_key               ,
    encapsulated_key            ,
    options    



     ,
  )                            {
    const { skR, pkR } = this.#extractRecipientKeys(private_key)
    this.#validateEncLength(encapsulated_key)

    let shared_secret            
    try {
      shared_secret = await this.#suite.KEM.Decap(encapsulated_key, skR, pkR)
    } catch (cause) {
      if (cause instanceof ValidationError || cause instanceof NotSupportedError) {
        throw cause
      }
      throw new DecapError('Decapsulation failed', { cause })
    }

    const mode = options?.psk ? MODE_PSK : MODE_BASE
    const { key, base_nonce, exporter_secret } = await KeySchedule(
      this.#suite,
      mode,
      shared_secret,
      options?.info,
      options?.psk,
      options?.psk_id,
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
  }
}







export class DeserializeError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DeserializeError'
  }
}







export class EncapError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'EncapError'
  }
}







export class DecapError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DecapError'
  }
}







export class OpenError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'OpenError'
  }
}







export class MessageLimitReachedError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'MessageLimitReachedError'
  }
}







export class DeriveKeyPairError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'DeriveKeyPairError'
  }
}







export class NotSupportedError extends Error {
  constructor(message         , options                      ) {
    super(message, options)
    this.name = 'NotSupportedError'
  }
}













export const MODE_BASE = 0x00


export const MODE_PSK = 0x01



















































































































function concat(...buffers              )             {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  for (const buffer of buffers) {
    buf.set(buffer, i)
    i += buffer.length
  }
  return buf
}

function encode(string        )             {
  const bytes = new Uint8Array(string.length)
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i)
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

async function ExportOneStage(
  KDF     ,
  suite_id            ,
  exporter_secret            ,
  exporter_context            ,
  L        ,
) {
  if (exporter_context.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `Exporter context length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  return await LabeledDerive(KDF, suite_id, exporter_secret, encode('sec'), exporter_context, L)
}

async function CombineSecretsOneStage(
  suite        ,
  mode        ,
  shared_secret            ,
  info            ,
  psk            ,
  psk_id            ,
) {
  if (psk.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `PSK length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  if (psk_id.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `PSK ID length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }
  if (info.byteLength > MAX_LENGTH_ONE_STAGE) {
    throw new TypeError(
      `Info length must not exceed ${MAX_LENGTH_ONE_STAGE} bytes for one-stage KDF`,
    )
  }

  const secrets = concat(lengthPrefixed(psk), lengthPrefixed(shared_secret))
  const context = concat(I2OSP(mode, 1), lengthPrefixed(psk_id), lengthPrefixed(info))

  const secret = await LabeledDerive(
    suite.KDF,
    suite.id,
    secrets,
    encode('secret'),
    context,
    suite.AEAD.Nk + suite.AEAD.Nn + suite.KDF.Nh,
  )

  const key = secret.slice(0, suite.AEAD.Nk)
  const base_nonce = secret.slice(suite.AEAD.Nk, suite.AEAD.Nk + suite.AEAD.Nn)
  const exporter_secret = secret.slice(suite.AEAD.Nk + suite.AEAD.Nn)

  return { key, base_nonce, exporter_secret }
}



const MAX_LENGTH_TWO_STAGE = 0xffff

const MAX_LENGTH_ONE_STAGE = 0xffff

async function CombineSecretsTwoStage(
  suite        ,
  mode        ,
  shared_secret            ,
  info            ,
  psk            ,
  psk_id            ,
) {
  if (psk.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `PSK length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  if (psk_id.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `PSK ID length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  if (info.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `Info length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }

  const [psk_id_hash, info_hash] = await Promise.all([
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), encode('psk_id_hash'), psk_id),
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), encode('info_hash'), info),
  ])

  const key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
  const secret = await LabeledExtract(suite.KDF, suite.id, shared_secret, encode('secret'), psk)


  if (suite.AEAD.id === EXPORT_ONLY) {
    const exporter_secret = await LabeledExpand(
      suite.KDF,
      suite.id,
      secret,
      encode('exp'),
      key_schedule_context,
      suite.KDF.Nh,
    )
    return { key: new Uint8Array(), base_nonce: new Uint8Array(), exporter_secret }
  }

  const [key, base_nonce, exporter_secret] = await Promise.all([
    LabeledExpand(suite.KDF, suite.id, secret, encode('key'), key_schedule_context, suite.AEAD.Nk),
    LabeledExpand(
      suite.KDF,
      suite.id,
      secret,
      encode('base_nonce'),
      key_schedule_context,
      suite.AEAD.Nn,
    ),
    LabeledExpand(suite.KDF, suite.id, secret, encode('exp'), key_schedule_context, suite.KDF.Nh),
  ])

  return { key, base_nonce, exporter_secret }
}

async function ExportTwoStage(
  KDF     ,
  suite_id            ,
  exporter_secret            ,
  exporter_context            ,
  L        ,
) {
  if (exporter_context.byteLength > MAX_LENGTH_TWO_STAGE) {
    throw new TypeError(
      `Exporter context length must not exceed ${MAX_LENGTH_TWO_STAGE} bytes for two-stage KDF`,
    )
  }
  return await LabeledExpand(KDF, suite_id, exporter_secret, encode('sec'), exporter_context, L)
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
      throw new TypeError('Invalid "private_key"', { cause })
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
    throw new TypeError(`Invalid "${type}_key"`)
  }

  if (extractable && k.extractable !== true) {
    throw new TypeError(`"${type}_key" must be extractable`)
  }
}












































































































function I2OSP(n        , w        )             {
  if (w <= 0) {
    throw new Error('w(length) <= 0')
  }
  const max = Math.pow(256, w)
  if (n >= max) {
    throw new Error('n too large')
  }
  const ret = new Uint8Array(w)
  let num = n
  for (let i = 0; i < w && num; i++) {
    ret[w - (i + 1)] = num % 256
    num = num >> 8
  }
  return ret
}

async function KeySchedule(
  suite        ,
  mode        ,
  shared_secret            ,
  info             ,
  psk             ,
  psk_id             ,
) {
  if (info != null && !(info instanceof Uint8Array)) {
    throw new TypeError('"info" must be an Uint8Array')
  }
  if (psk != null && !(psk instanceof Uint8Array)) {
    throw new TypeError('"psk" must be an Uint8Array')
  }
  if (psk_id != null && !(psk_id instanceof Uint8Array)) {
    throw new TypeError('"psk_id" must be an Uint8Array')
  }
  VerifyPSKInputs(psk, psk_id)

  info ??= new Uint8Array()
  psk ??= new Uint8Array()
  psk_id ??= new Uint8Array()


  if (suite.KDF.stages !== 1 && suite.KDF.stages !== 2) {
    throw new Error('unreachable')
  }
  const CombineSecrets = suite.KDF.stages === 1 ? CombineSecretsOneStage : CombineSecretsTwoStage

  return await CombineSecrets(suite, mode, shared_secret, info, psk, psk_id)
}

function VerifyPSKInputs(psk             , psk_id             ) {
  if (psk?.byteLength && psk_id?.byteLength) {
    if (psk.byteLength < 32) {
      throw new TypeError('Insufficient PSK length')
    }
    return
  }
  if (!psk?.byteLength && !psk_id?.byteLength) {
    return
  }
  throw new TypeError('Inconsistent PSK inputs')
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





async function subtle   (promise                  , name        )             {
  try {
    return await promise()
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
  return typeof SharedArrayBuffer === 'undefined' || input instanceof SharedArrayBuffer
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
          async () =>
            crypto.subtle.sign(
              'HMAC',
              await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: this.hash }, false, [
                'sign',
              ]),
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
        () =>
          crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: this.hash }, false, ['sign']),
        this.name,
      )

      const T = new Uint8Array(N * this.Nh)
      let T_prev = new Uint8Array()

      for (let i = 0; i < N; i++) {
        const input = new Uint8Array(T_prev.byteLength + info.byteLength + 1)
        input.set(T_prev)
        input.set(info, T_prev.byteLength)
        input[T_prev.byteLength + info.byteLength] = i + 1

        const T_i = new Uint8Array(
          await subtle(() => crypto.subtle.sign('HMAC', key, input), this.name),
        )

        T.set(T_i, i * this.Nh)
        T_prev = T_i
      }

      return T.slice(0, L)
    },
  }
}



















export const KDF_HKDF_SHA256             = function ()       {
  return {
    id: 0x0001,
    type: 'KDF',
    name: 'HKDF-SHA256',
    Nh: 32,
    hash: 'SHA-256',
    ...HKDF_SHARED(),
  }
}















export const KDF_HKDF_SHA384             = function ()       {
  return {
    id: 0x0002,
    type: 'KDF',
    name: 'HKDF-SHA384',
    Nh: 48,
    hash: 'SHA-384',
    ...HKDF_SHARED(),
  }
}















export const KDF_HKDF_SHA512             = function ()       {
  return {
    id: 0x0003,
    type: 'KDF',
    name: 'HKDF-SHA512',
    Nh: 64,
    hash: 'SHA-512',
    ...HKDF_SHARED(),
  }
}









async function ShakeDerive(name        , variant        , ikm             , L        ) {
  return new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.digest(
          {
            name: variant,

            length: L << 3,
          },
          ikm,
        ),
      name,
    ),
  )
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
    throw new TypeError('"private_key" must be extractable in this runtime')
  }

  return await subtle(async () => {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    return await crypto.subtle.importKey(
      'jwk',
      {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
      }              ,
      key.algorithm,
      true,
      usages,
    )
  }, name)
}

async function getPublicKey(name        , key           , usages            )                     {
  return (

    ((await subtle(() => crypto.subtle.getPublicKey?.(key, usages), name))             ) ||
    (await getPublicKeyByExport(name, key, usages))
  )
}


function checkNotAllZeros(buffer            )       {
  let allZeros = 1
  for (let i = 0; i < buffer.length; i++) {
    allZeros &= buffer[i]  === 0 ? 1 : 0
  }
  if (allZeros === 1) {
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

function b64u(input        )             {

  return Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fromBase64(input)
}





async function DeriveCandidate(
  DHKEM       ,
  suite_id            ,
  ikm            ,
  counter        ,
) {
  const dkp_prk = await LabeledExtract(
    DHKEM.kdf,
    suite_id,
    new Uint8Array(),
    encode('dkp_prk'),
    ikm,
  )
  return await LabeledExpand(
    DHKEM.kdf,
    suite_id,
    dkp_prk,
    encode('candidate'),
    I2OSP(counter, 1),
    DHKEM.Nsk,
  )
}

function OS2IP(x            )         {
  let result = 0n
  for (let i = 0; i < x.byteLength; i++) {
    result = result * 256n + BigInt(x[i] )
  }
  return result
}

function bigIntToUint8Array(value        , byteLength        )             {
  const result = new Uint8Array(byteLength)
  let n = value

  for (let i = byteLength - 1; i >= 0; i--) {
    result[i] = Number(n & 0xffn)
    n = n >> 8n
  }

  return result
}

function assertKeyAlgorithm(key     , expectedAlgorithm              ) {
  if (key.algorithm.name !== expectedAlgorithm.name) {
    throw new TypeError(`key algorithm must be ${expectedAlgorithm.name}`)
  }
  if (
    (key.algorithm                  ).namedCurve !==
    (expectedAlgorithm                  ).namedCurve
  ) {
    throw new TypeError(
      `key namedCurve must be ${(expectedAlgorithm                  ).namedCurve}`,
    )
  }
}

function assertCryptoKey(key     )                           {

  if (key[Symbol.toStringTag] !== 'CryptoKey') {
    if (key instanceof CryptoKey) return
    throw new TypeError('unexpected key constructor')
  }
}





function DHKEM_SHARED()                                            {
  return {
    async GenerateKeyPair(             extractable) {
      return (await subtle(
        () => crypto.subtle.generateKey(this.algorithm, extractable, ['deriveBits']),
        this.name,
      ))                 
    },
    async SerializePublicKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey('raw', key), this.name))
    },
    async DeserializePublicKey(             _key) {
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey('raw', key, this.algorithm, true, []),
        this.name,
      )
    },
    async SerializePrivateKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      const { d } = await subtle(() => crypto.subtle.exportKey('jwk', key), this.name)
      return b64u(d )
    },
    async DeserializePrivateKey(             key, extractable) {
      return await CurveKeyFromD(this, this.Nsk, this.pkcs8, this.algorithm, key, extractable)
    },
    async Encap(             pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      assertCryptoKey(pkR)

      const ekp = (await this.GenerateKeyPair(false))                 
      const skE = ekp.privateKey
      const pkE = ekp.publicKey



      const dh = new Uint8Array(
        await subtle(
          () =>
            crypto.subtle.deriveBits(
              {
                name: skE.algorithm.name,
                public: pkR,
              },
              skE,
              this.Ndh << 3,
            ),
          this.name,
        ),
      )
      checkNotAllZeros(dh)

      const enc = await this.SerializePublicKey(pkE)
      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(
        this.kdf,
        this.suite_id,
        new Uint8Array(),
        encode('eae_prk'),
        dh,
      )
      const shared_secret = await LabeledExpand(
        this.kdf,
        this.suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        this.Nsecret,
      )
      return { shared_secret, enc }
    },
    async Decap(             enc, skR, pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      assertCryptoKey(skR)
      if (pkR) {
        assertKeyAlgorithm(pkR, this.algorithm)
        assertCryptoKey(pkR)
      } else {
        pkR = await getPublicKey(this.name, skR, [])
      }

      const pkE = (await this.DeserializePublicKey(enc))             



      const dh = new Uint8Array(
        await subtle(
          () =>
            crypto.subtle.deriveBits(
              {
                name: skR.algorithm.name,
                public: pkE,
              },
              skR,
              this.Ndh << 3,
            ),
          this.name,
        ),
      )
      checkNotAllZeros(dh)

      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const eae_prk = await LabeledExtract(
        this.kdf,
        this.suite_id,
        new Uint8Array(),
        encode('eae_prk'),
        dh,
      )
      const shared_secret = await LabeledExpand(
        this.kdf,
        this.suite_id,
        eae_prk,
        encode('shared_secret'),
        kem_context,
        this.Nsecret,
      )
      return shared_secret
    },
  }
}





async function createKeyPairFromPrivateKey(
  DHKEM       ,
  key            ,
  extractable         ,
)                         {
  let privateKey           
  let publicKey           

  if (!extractable && typeof crypto.subtle.getPublicKey !== 'function') {
    privateKey = (await DHKEM.DeserializePrivateKey(key, true))             
    publicKey = await getPublicKey(DHKEM.name, privateKey, [])
    privateKey = (await DHKEM.DeserializePrivateKey(key, false))             
  } else {
    privateKey = (await DHKEM.DeserializePrivateKey(key, extractable))             
    publicKey = await getPublicKey(DHKEM.name, privateKey, [])
  }
  return { privateKey, publicKey }
}

async function CurveKeyFromD(
  KEM     ,
  Nsk        ,
  template            ,
  algorithm              ,
  key            ,
  extractable         ,
) {
  const tmpl = template.slice()
  const pkcs8 = new Uint8Array(Nsk + tmpl.byteLength)
  pkcs8.set(tmpl)
  pkcs8.set(key, tmpl.byteLength)
  return await subtle(
    () => crypto.subtle.importKey('pkcs8', pkcs8, algorithm, extractable, ['deriveBits']),
    KEM.name,
  )
}





async function DeriveKeyPairNist(

  ikm            ,
  extractable         ,
) {
  let sk = 0n
  let counter = 0
  while (sk === 0n || sk >= this.order) {
    if (counter > 255) {
      throw new DeriveKeyPairError('Key derivation exceeded maximum iterations')
    }
    const bytes = await DeriveCandidate(this, this.suite_id, ikm, counter)
    bytes[0] = bytes[0]  & this.bitmask
    sk = OS2IP(bytes)
    counter = counter + 1
  }
  const key = bigIntToUint8Array(sk, this.Nsk)
  return await createKeyPairFromPrivateKey(this, key, extractable)
}





async function DeriveKeyPairX(             ikm            , extractable         ) {
  const dkp_prk = await LabeledExtract(
    this.kdf,
    this.suite_id,
    new Uint8Array(),
    encode('dkp_prk'),
    ikm,
  )
  const sk = await LabeledExpand(
    this.kdf,
    this.suite_id,
    dkp_prk,
    encode('sk'),
    new Uint8Array(),
    this.Nsk,
  )
  return await createKeyPairFromPrivateKey(this, sk, extractable)
}




















export const KEM_DHKEM_P256_HKDF_SHA256             = function ()        {
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
    Npk: 65,
    Nsk: 32,
    Ndh: 32,
    algorithm: { name: 'ECDH', namedCurve: 'P-256' },
    order: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    bitmask: 0xff,
    pkcs8: Uint8Array.of(0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20),
    DeriveKeyPair: DeriveKeyPairNist,
    ...DHKEM_SHARED(),
  }
}
















export const KEM_DHKEM_P384_HKDF_SHA384             = function ()        {
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
    Npk: 97,
    Nsk: 48,
    Ndh: 48,
    algorithm: { name: 'ECDH', namedCurve: 'P-384' },
    order: BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
    bitmask: 0xff,
    pkcs8: Uint8Array.of(0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x30),
    DeriveKeyPair: DeriveKeyPairNist,
    ...DHKEM_SHARED(),
  }
}
















export const KEM_DHKEM_P521_HKDF_SHA512             = function ()        {
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
    Npk: 133,
    Nsk: 66,
    Ndh: 66,
    algorithm: { name: 'ECDH', namedCurve: 'P-521' },
    order: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
    bitmask: 0x01,
    pkcs8: Uint8Array.of(0x30, 0x60, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x04, 0x49, 0x30, 0x47, 0x02, 0x01, 0x01, 0x04, 0x42),
    DeriveKeyPair: DeriveKeyPairNist,
    ...DHKEM_SHARED(),
  }
}




















export const KEM_DHKEM_X25519_HKDF_SHA256             = function ()        {
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
    ...DHKEM_SHARED(),
  }
}
















export const KEM_DHKEM_X448_HKDF_SHA512             = function ()        {
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
        () => crypto.subtle.generateKey(this.algorithm, extractable, usages),
        this.name,
      ))                 
    },
    async SerializePublicKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)

      const format                            = 'raw-public'
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey(format, key), this.name))
    },
    async DeserializePublicKey(             _key) {

      const format                            = 'raw-public'

      const usages             = ['encapsulateBits']
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey(format, key, this.algorithm, true, usages),
        this.name,
      )
    },
    async SerializePrivateKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)

      const format                            = 'raw-seed'
      return new Uint8Array(await subtle(() => crypto.subtle.exportKey(format, key), this.name))
    },
    async DeserializePrivateKey(             _key, extractable) {

      const format                            = 'raw-seed'

      const usages             = ['decapsulateBits']
      const key = ab(_key)
      return await subtle(
        () => crypto.subtle.importKey(format, key, this.algorithm, extractable, usages),
        this.name,
      )
    },
    async Encap(             pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)

      const { sharedKey, ciphertext } = (await subtle(
        () =>

          crypto.subtle.encapsulateBits(this.algorithm, pkR),
        this.name,
      ))                                                       

      return {
        shared_secret: new Uint8Array(sharedKey),
        enc: new Uint8Array(ciphertext),
      }
    },
    async Decap(             _enc, skR, _pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      const enc = ab(_enc)
      return new Uint8Array(
        await subtle(
          () =>

            crypto.subtle.decapsulateBits(this.algorithm, skR, enc),
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
          async () =>
            crypto.subtle.encrypt(
              {
                name: this.algorithm,
                iv: nonce,
                additionalData: aad,
              },
              await crypto.subtle.importKey(this.keyFormat, key, this.algorithm, false, [
                'encrypt',
              ]),
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
          async () =>
            crypto.subtle.decrypt(
              {
                name: this.algorithm,
                iv: nonce,
                additionalData: aad,
              },
              await crypto.subtle.importKey(this.keyFormat, key, this.algorithm, false, [
                'decrypt',
              ]),
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





const priv = Symbol()
class HybridKey                {
  #algorithm              

  #type                      

  #extractable         

  #t           

  #pq           

  #seed                         

  #publicKey                        

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
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
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
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
    return this.#publicKey
  }

  getSeed(_             ) {
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
    return this.#seed .slice()
  }

  getT(_             ) {
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
    return this.#t
  }

  getPq(_             ) {
    if (_ !== priv) {
      throw new Error('invalid invocation')
    }
    return this.#pq
  }
}

function split(N1        , N2        , x            )                           {
  if (x.byteLength !== N1 + N2) {
    throw new Error('x.byteLength !== N1 + N2')
  }

  const x1 = x.slice(0, N1)
  const x2 = x.slice(-N2)

  return [x1, x2]
}

function RandomScalarNist(t                , seed            )             {
  let sk_bigint = 0n
  let start = 0
  let end = t.Nscalar 
  sk_bigint = OS2IP(seed.slice(start, end))

  while (sk_bigint === 0n || sk_bigint >= t.order ) {
    start = end
    end = end + t.Nscalar 
    if (end > seed.byteLength) {
      throw new DeriveKeyPairError('Rejection sampling failed')
    }
    sk_bigint = OS2IP(seed.slice(start, end))
  }
  return bigIntToUint8Array(sk_bigint, t.Nscalar )
}

async function expandDecapsKeyG(PQTKEM           , _seed            ) {
  const Nout = PQTKEM.pq.Nseed + PQTKEM.t.Nseed

  const algorithm               = { name: 'cSHAKE256', length: Nout << 3 }
  const seed = ab(_seed)
  const seed_full = await subtle(() => crypto.subtle.digest(algorithm, seed), PQTKEM.name)

  const [_seed_PQ, seed_T] = split(PQTKEM.pq.Nseed, PQTKEM.t.Nseed, new Uint8Array(seed_full))
  const seed_PQ = ab(_seed_PQ)


  const format                            = 'raw-seed'

  const usages                       = ['decapsulateBits', 'encapsulateBits']
  const dk_PQ = await subtle(
    () => crypto.subtle.importKey(format, seed_PQ, PQTKEM.pq.algorithm, true, [usages[0]]),
    PQTKEM.name,
  )
  const ek_PQ = await getPublicKey(PQTKEM.name, dk_PQ, [usages[1]])
  const sk = PQTKEM.t.RandomScalar?.(seed_T) ?? seed_T

  const dk_T = await CurveKeyFromD(
    PQTKEM,
    PQTKEM.t.Nsk,
    PQTKEM.t.pkcs8,
    PQTKEM.t.algorithm,
    sk,
    true,
  )
  const ek_T = await getPublicKey(PQTKEM.name, dk_T, [])

  return { ek_PQ, ek_T, dk_PQ, dk_T }
}

async function C2PRICombiner(
  PQTKEM           ,
  ss_PQ            ,
  ss_T            ,
  ct_T            ,
  _ek_T           ,
  label            ,
)                      {
  const ek_T = new Uint8Array(
    await subtle(() => crypto.subtle.exportKey('raw', _ek_T), PQTKEM.name),
  )
  const data = ab(concat(ss_PQ, ss_T, ct_T, ek_T, label))
  return new Uint8Array(await subtle(() => crypto.subtle.digest('SHA3-256', data), PQTKEM.name))
}

async function prepareEncapsG(
  PQTKEM           ,
  ek_PQ           ,
  ek_T           ,
)                                                            {
  const res = (await subtle(
    () =>

      crypto.subtle.encapsulateBits(PQTKEM.pq.algorithm, ek_PQ),
    PQTKEM.name,
  ))                                                       
  const ss_PQ = new Uint8Array(res.sharedKey)
  const ct_PQ = new Uint8Array(res.ciphertext)

  const { privateKey: sk_E, publicKey } = (await subtle(
    () => crypto.subtle.generateKey(PQTKEM.t.algorithm, true, ['deriveBits']),
    PQTKEM.name,
  ))                 
  const ct_T = new Uint8Array(
    await subtle(() => crypto.subtle.exportKey('raw', publicKey), PQTKEM.name),
  )

  const ss_T = new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.deriveBits(
          {
            name: PQTKEM.t.algorithm.name,
            public: ek_T,
          },
          sk_E,
          PQTKEM.t.Nss << 3,
        ),
      PQTKEM.name,
    ),
  )
  checkNotAllZeros(ss_T)

  return [ss_PQ, ss_T, ct_PQ, ct_T]
}

function assertHybridKey(key     )                           {
  if (!(key instanceof HybridKey) || Object.getPrototypeOf(key) !== HybridKey.prototype) {
    throw new TypeError('unexpected key constructor')
  }
}

async function prepareDecapsG(
  PQTKEM           ,
  dk_PQ           ,
  dk_T           ,
  ct_PQ            ,
  _ct_T            ,
)                                    {
  const ss_PQ = new Uint8Array(
    await subtle(
      () =>

        crypto.subtle.decapsulateBits(PQTKEM.pq.algorithm, dk_PQ, ct_PQ),
      PQTKEM.name,
    ),
  )

  const ct_T = ab(_ct_T)
  const pub = await subtle(
    () => crypto.subtle.importKey('raw', ct_T, PQTKEM.t.algorithm, true, []),
    PQTKEM.name,
  )

  const ss_T = new Uint8Array(
    await subtle(
      () =>
        crypto.subtle.deriveBits(
          {
            name: PQTKEM.t.algorithm.name,
            public: pub,
          },
          dk_T,
          PQTKEM.t.Nss << 3,
        ),
      PQTKEM.name,
    ),
  )
  checkNotAllZeros(ss_T)

  return [ss_PQ, ss_T]
}


























function PQTKEM_SHARED()           {
  Object.freeze(HybridKey.prototype)
  return {
    async DeriveKeyPair(                 ikm            , extractable) {
      const seed = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        encode('DeriveKeyPair'),
        new Uint8Array(),
        32,
      )

      const { ek_PQ, ek_T, dk_PQ, dk_T } = await expandDecapsKeyG(this, seed)

      const publicKey = new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
      const privateKey = new HybridKey(
        priv,
        this.algorithm,
        'private',
        extractable,
        dk_PQ,
        dk_T,
        seed,
        publicKey,
      )

      return { privateKey, publicKey }
    },
    async GenerateKeyPair(                 extractable) {
      return await this.DeriveKeyPair(crypto.getRandomValues(new Uint8Array(32)), extractable)
    },
    async SerializePublicKey(                 key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertHybridKey(key)

      const format                            = 'raw-public'
      const ek_PQ = new Uint8Array(
        await subtle(() => crypto.subtle.exportKey(format, key.getPq(priv)), this.name),
      )
      const ek_T = new Uint8Array(
        await subtle(() => crypto.subtle.exportKey('raw', key.getT(priv)), this.name),
      )

      return concat(ek_PQ, ek_T)
    },
    async DeserializePublicKey(                 key) {

      const format                            = 'raw-public'

      const usages             = ['encapsulateBits']
      const pubPq = ab(key.subarray(0, this.pq.Npk))
      const pubT = ab(key.subarray(this.pq.Npk))
      const [ek_PQ, ek_T] = await Promise.all([
        subtle(
          () => crypto.subtle.importKey(format, pubPq, this.pq.algorithm, true, usages),
          this.name,
        ),
        subtle(() => crypto.subtle.importKey('raw', pubT, this.t.algorithm, true, []), this.name),
      ])

      return new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
    },
    async SerializePrivateKey(                 key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertHybridKey(key)

      return key.getSeed(priv)
    },
    async DeserializePrivateKey(                 key, extractable) {
      const { ek_PQ, ek_T, dk_PQ, dk_T } = await expandDecapsKeyG(this, key)
      const publicKey = new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
      const privateKey = new HybridKey(
        priv,
        this.algorithm,
        'private',
        extractable,
        dk_PQ,
        dk_T,
        key.slice(),
        publicKey,
      )

      return privateKey
    },
    async Encap(                 pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      assertHybridKey(pkR)

      const ek_PQ = pkR.getPq(priv)
      const ek_T = pkR.getT(priv)
      const [ss_PQ, ss_T, ct_PQ, ct_T] = await prepareEncapsG(this, ek_PQ, ek_T)
      const ss_H = await C2PRICombiner(this, ss_PQ, ss_T, ct_T, ek_T, this.label)
      const ct_H = concat(ct_PQ, ct_T)

      return { shared_secret: ss_H, enc: ct_H }
    },
    async Decap(                 enc, skR, pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      assertHybridKey(skR)

      if (pkR) {
        assertKeyAlgorithm(pkR, this.algorithm)
        assertHybridKey(pkR)
      }

      const [ct_PQ, ct_T] = split(this.pq.Nct, this.t.Nct, enc)
      const ek = pkR ?? skR.getPublicKey(priv) 
      const ek_T = ek.getT(priv)
      const dk_PQ = skR.getPq(priv)
      const dk_T = skR.getT(priv)
      const [ss_PQ, ss_T] = await prepareDecapsG(this, dk_PQ, dk_T, ct_PQ, ct_T)
      const ss_H = await C2PRICombiner(this, ss_PQ, ss_T, ct_T, ek_T, this.label)

      return ss_H
    },
  }
}



















export const KEM_MLKEM768_X25519             = function ()            {
  const id = 0x647a
  const name = 'MLKEM768-X25519'
  const kdf = KDF_SHAKE256()

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
    pq: {
      algorithm: { name: 'ML-KEM-768' },
      Nseed: 64,
      Npk: 1184,
      Nct: 1088,
    },
    t: {
      algorithm: { name: 'X25519' },
      Nseed: 32,
      Npk: 32,
      Nss: 32,
      Nsk: 32,
      Nct: 32,
      pkcs8: Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20),
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
    pq: {
      algorithm: { name: 'ML-KEM-768' },
      Nseed: 64,
      Npk: 1184,
      Nct: 1088,
    },
    t: {
      algorithm: { name: 'ECDH', namedCurve: 'P-256' },
      Nseed: 32,
      Npk: 65,
      Nss: 32,
      Nsk: 32,
      Nct: 65,
      pkcs8: Uint8Array.of(0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20),
      Nscalar: 32,
      order: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
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
    pq: {
      algorithm: { name: 'ML-KEM-1024' },
      Nseed: 64,
      Npk: 1568,
      Nct: 1568,
    },
    t: {
      algorithm: { name: 'ECDH', namedCurve: 'P-384' },
      Nseed: 48,
      Npk: 65,
      Nss: 48,
      Nsk: 48,
      Nct: 97,
      pkcs8: Uint8Array.of(0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x30),
      Nscalar: 48,
      order: BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
      RandomScalar(seed) {
        return RandomScalarNist(this, seed)
      },
    },
    label: Uint8Array.of(0x4d, 0x4c, 0x4b, 0x45, 0x4d, 0x31, 0x30, 0x32, 0x34, 0x2d, 0x50, 0x33, 0x38, 0x34),
    ...PQTKEM_SHARED(),
  }
}
