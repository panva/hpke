







































 
 
 

 
function ComputeNonce(base_nonce            , seq        , Nn        )             {
   
   
   
  const nonce = new Uint8Array(Nn)
  nonce.set(base_nonce)
  let s = seq
  for (let i = Nn - 1; i >= 0 && s > 0; i--) {
    nonce[i] = nonce[i]  ^ (s & 0xff)
    s = Math.floor(s / 256)
  }
  return nonce
}

function MaxSeq(Nn        )         {
   
   
  return Math.min(2 ** (8 * Nn) - 1, Number.MAX_SAFE_INTEGER)
}

 
function IncrementSeq(seq        , maxSeq        )         {
  if (seq >= maxSeq) {
    throw new MessageLimitReachedError('Sequence number overflow')
  }
  return ++seq
}

 
async function ContextExport(
  suite        ,
  exporterSecret            ,
  exporterContext            ,
  L        ,
) {
  checkUint8Array(exporterContext, 'exporterContext')
  const stages = KDFStages(suite.KDF)
  if (!Number.isInteger(L) || L <= 0 || L > 0xffff) {
    throw new TypeError('"L" must be a positive integer not exceeding 65535')
  }
  if (stages === 2 && L > 255 * suite.KDF.Nh) {
    throw new TypeError('"L" must not exceed 255*Nh of the cipher suite KDF')
  }
  const Export = stages === 1 ? Export_OneStage : Export_TwoStage
  return await Export(suite.KDF, suite.id, exporterSecret, exporterContext, L)
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

                        
                        
                     
                          
                                 
                                      
                          
             
               
 

function createContextState(
  suite        ,
  mode      ,
  key            ,
  base_nonce            ,
  exporter_secret            ,
)               {
  return {
    suite,
    mode,
    key,
    base_nonce,
    exporter_secret,
    max_seq: MaxSeq(suite.AEAD.Nn),
    seq: 0,
    mutex: undefined,
  }
}




















class SenderContext {
  #state              

  constructor(
    suite        ,
    mode      ,
    key            ,
    base_nonce            ,
    exporter_secret            ,
  ) {
    this.#state = createContextState(suite, mode, key, base_nonce, exporter_secret)
  }

  




  get mode()       {
    return this.#state.mode
  }

  





  get seq()         {
    return this.#state.seq
  }

  

























  async Seal(plaintext            , aad             )                      {
    checkUint8Array(plaintext, 'plaintext')
    aad ??= new Uint8Array()
    checkUint8Array(aad, 'aad')
    const state = this.#state
    if (state.suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Seal')
    }

    state.mutex ??= new Mutex()
    const release = await state.mutex.lock()
    let ct            
    try {
      ct = await state.suite.AEAD.Seal(
        state.key,
        ComputeNonce(state.base_nonce, state.seq, state.suite.AEAD.Nn),
        aad,
        plaintext,
      )
      state.seq = IncrementSeq(state.seq, state.max_seq)
      return ct
    } finally {
      release()
    }
  }

  






















  async Export(exporterContext            , length        )                      {
    return await ContextExport(
      this.#state.suite,
      this.#state.exporter_secret,
      exporterContext,
      length,
    )
  }

  



  get Nt()         {
    return this.#state.suite.AEAD.Nt
  }
}
                             




















class RecipientContext {
  #state              

  constructor(
    suite        ,
    mode      ,
    key            ,
    base_nonce            ,
    exporter_secret            ,
  ) {
    this.#state = createContextState(suite, mode, key, base_nonce, exporter_secret)
  }

  




  get mode()       {
    return this.#state.mode
  }

  





  get seq()         {
    return this.#state.seq
  }

  


























  async Open(ciphertext            , aad             )                      {
    checkUint8Array(ciphertext, 'ciphertext')
    aad ??= new Uint8Array()
    checkUint8Array(aad, 'aad')

    const state = this.#state
    if (state.suite.AEAD.id === EXPORT_ONLY) {
      throw new TypeError('Export-only AEAD cannot be used with Open')
    }

    state.mutex ??= new Mutex()
    const release = await state.mutex.lock()
    try {
      let pt            
      try {
        pt = await state.suite.AEAD.Open(
          state.key,
          ComputeNonce(state.base_nonce, state.seq, state.suite.AEAD.Nn),
          aad,
          ciphertext,
        )
      } catch (cause) {
        if (cause instanceof MessageLimitReachedError || cause instanceof NotSupportedError) {
          throw cause
        }

        throw new OpenError('AEAD decryption failed', { cause })
      }
      state.seq = IncrementSeq(state.seq, state.max_seq)
      return pt
    } finally {
      release()
    }
  }

  






















  async Export(exporterContext            , length        )                      {
    return await ContextExport(
      this.#state.suite,
      this.#state.exporter_secret,
      exporterContext,
      length,
    )
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

























export class CipherSuite                      {
  #suite           

  




























































  constructor(KEM               , KDF            , AEAD             ) {
    const kem = validate(KEM, 'KEM')
    const kdf = validate(KDF, 'KDF')
    const aead = validate(AEAD, 'AEAD')

    this.#suite = {
      KEM: kem,
      KDF: kdf,
      AEAD: aead,
      id: concat(L_HPKE, I2OSP(kem.id, 2), I2OSP(kdf.id, 2), I2OSP(aead.id, 2)),
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

  
















  async GenerateKeyPair(extractable          )                      {
    extractable ??= false
    checkExtractable(extractable)
    return await this.#suite.KEM.GenerateKeyPair(extractable)
  }

  


























  async DeriveKeyPair(ikm            , extractable          )                      {
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

  















  async SerializePrivateKey(privateKey   )                      {
    isKey(privateKey, 'private', true)

    return await this.#suite.KEM.SerializePrivateKey(privateKey)
  }

  















  async SerializePublicKey(publicKey   )                      {
    isKey(publicKey, 'public', true)

    return await this.#suite.KEM.SerializePublicKey(publicKey)
  }

  


















  async DeserializePrivateKey(privateKey            , extractable          )             {
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

  
















  async DeserializePublicKey(publicKey            )             {
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
    publicKey   ,
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
    privateKey                ,
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
    publicKey   ,
    exporterContext            ,
    length        ,
    options                                                              ,
  )                                                                          {
    const { encapsulatedSecret, ctx } = await this.SetupSender(publicKey, options)
    const exportedSecret = await ctx.Export(exporterContext, length)
    return { encapsulatedSecret, exportedSecret }
  }

  




































  async ReceiveExport(
    privateKey                ,
    encapsulatedSecret            ,
    exporterContext            ,
    length        ,
    options                                                              ,
  )                      {
    const ctx = await this.SetupRecipient(privateKey, encapsulatedSecret, options)
    return await ctx.Export(exporterContext, length)
  }

  










































  async SetupSender(
    publicKey   ,
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
    privateKey                ,
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

  #extractRecipientKeys(skR                )                                 {
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

 
 
 
 
const L_HPKE_v1 = /* @__PURE__ */ encode('HPKE-v1')
const L_HPKE = /* @__PURE__ */ encode('HPKE')
const L_KEM = /* @__PURE__ */ encode('KEM')
const L_sec = /* @__PURE__ */ encode('sec')
const L_secret = /* @__PURE__ */ encode('secret')
const L_key = /* @__PURE__ */ encode('key')
const L_base_nonce = /* @__PURE__ */ encode('base_nonce')
const L_exp = /* @__PURE__ */ encode('exp')
const L_psk_id_hash = /* @__PURE__ */ encode('psk_id_hash')
const L_info_hash = /* @__PURE__ */ encode('info_hash')
const L_dkp_prk = /* @__PURE__ */ encode('dkp_prk')
const L_candidate = /* @__PURE__ */ encode('candidate')
const L_eae_prk = /* @__PURE__ */ encode('eae_prk')
const L_shared_secret = /* @__PURE__ */ encode('shared_secret')
const L_sk = /* @__PURE__ */ encode('sk')
const L_public_key_recovery = /* @__PURE__ */ encode('HPKE public key recovery')
const L_DeriveKeyPair = /* @__PURE__ */ encode('DeriveKeyPair')

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
  const labeled_ikm = concat(ikm, L_HPKE_v1, suite_id, lengthPrefixed(label), I2OSP(L, 2), context)
  return await KDF.Derive(labeled_ikm, L)
}

 
async function Export_OneStage(
  KDF     ,
  suite_id            ,
  exporter_secret            ,
  exporter_context            ,
  L        ,
) {
  checkLength(exporter_context, 'Exporter context', MAX_LENGTH_ONE_STAGE)
  return await LabeledDerive(KDF, suite_id, exporter_secret, L_sec, exporter_context, L)
}

 
async function CombineSecrets_OneStage(
  suite        ,
  mode        ,
  shared_secret            ,
  info            ,
  psk            ,
  psk_id            ,
) {
  checkLength(psk, 'PSK', MAX_LENGTH_ONE_STAGE)
  checkLength(psk_id, 'PSK ID', MAX_LENGTH_ONE_STAGE)
  checkLength(info, 'Info', MAX_LENGTH_ONE_STAGE)

  const secrets = concat(lengthPrefixed(psk), lengthPrefixed(shared_secret))
  const context = concat(I2OSP(mode, 1), lengthPrefixed(psk_id), lengthPrefixed(info))

  const secret = await LabeledDerive(
    suite.KDF,
    suite.id,
    secrets,
    L_secret,
    context,
    suite.AEAD.Nk + suite.AEAD.Nn + suite.KDF.Nh,
  )

  const key = slice(secret, 0, suite.AEAD.Nk)
  const base_nonce = slice(secret, suite.AEAD.Nk, suite.AEAD.Nk + suite.AEAD.Nn)
  const exporter_secret = slice(secret, suite.AEAD.Nk + suite.AEAD.Nn)

  return { key, base_nonce, exporter_secret }
}

 
 
const MAX_LENGTH_TWO_STAGE = 0xffff
 
const MAX_LENGTH_ONE_STAGE = 0xffff

function checkLength(data            , name        , maxLength        ) {
  if (data.byteLength > maxLength) {
    throw new TypeError(`${name} length must not exceed ${maxLength} bytes`)
  }
}
function checkUint8Array(input         , name        )                              {
  if (!(input instanceof Uint8Array)) {
    throw new TypeError(`"${name}" must be Uint8Array`)
  }
  if (typeof SharedArrayBuffer !== 'undefined' && input.buffer instanceof SharedArrayBuffer) {
    throw new TypeError(`"${name}" must not be backed by a SharedArrayBuffer`)
  }
}
function checkExtractable(extractable         )                                 {
  if (typeof extractable !== 'boolean') {
    throw new TypeError('"extractable" must be boolean')
  }
}

 
async function CombineSecrets_TwoStage(
  suite        ,
  mode        ,
  shared_secret            ,
  info            ,
  psk            ,
  psk_id            ,
) {
  checkLength(psk, 'PSK', MAX_LENGTH_TWO_STAGE)
  checkLength(psk_id, 'PSK ID', MAX_LENGTH_TWO_STAGE)
  checkLength(info, 'Info', MAX_LENGTH_TWO_STAGE)

  const [psk_id_hash, info_hash] = await Promise.all([
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), L_psk_id_hash, psk_id),
    LabeledExtract(suite.KDF, suite.id, new Uint8Array(), L_info_hash, info),
  ])

  const key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
  const secret = await LabeledExtract(suite.KDF, suite.id, shared_secret, L_secret, psk)

   
  if (suite.AEAD.id === EXPORT_ONLY) {
    const exporter_secret = await LabeledExpand(
      suite.KDF,
      suite.id,
      secret,
      L_exp,
      key_schedule_context,
      suite.KDF.Nh,
    )
    return { key: new Uint8Array(), base_nonce: new Uint8Array(), exporter_secret }
  }

  const [key, base_nonce, exporter_secret] = await Promise.all([
    LabeledExpand(suite.KDF, suite.id, secret, L_key, key_schedule_context, suite.AEAD.Nk),
    LabeledExpand(suite.KDF, suite.id, secret, L_base_nonce, key_schedule_context, suite.AEAD.Nn),
    LabeledExpand(suite.KDF, suite.id, secret, L_exp, key_schedule_context, suite.KDF.Nh),
  ])

  return { key, base_nonce, exporter_secret }
}

 
async function Export_TwoStage(
  KDF     ,
  suite_id            ,
  exporter_secret            ,
  exporter_context            ,
  L        ,
) {
  checkLength(exporter_context, 'Exporter context', MAX_LENGTH_TWO_STAGE)
  return await LabeledExpand(KDF, suite_id, exporter_secret, L_sec, exporter_context, L)
}




































































                      
                                 
                     

                                         
                      

                                                 
                       

     
                                                                   
    
                                                                                  
     
                     

                                                                        
                        

     
                                                            
    
                             
                                       
    
                                                         
     
                                                                 

     
                                                      
    
                                  
                                                               
                                                                 
    
                                                               
     
                                                                           

     
                                                                                
    
                                                       
                                                                 
    
                                                               
     
                                                                 
 

 
 
 


















export async function LabeledExtract(
  KDF                      ,
  suite_id            ,
  salt            ,
  label            ,
  ikm            ,
)                      {
  const labeled_ikm = concat(L_HPKE_v1, suite_id, label, ikm)
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
  const labeled_info = concat(I2OSP(L, 2), L_HPKE_v1, suite_id, label, info)
  return await KDF.Expand(prk, labeled_info, L)
}

 
 
 































































































                                           
                                 
                     

                                         
                      

                                                 
                       

                                                                    
                          

                                                                       
                       

                                                     
                      

                                                      
                      

     
                                                                     
    
                                                                                          
                                                                       
    
                                                      
     
                                                                           

     
                                 
    
                                                                       
    
                                                      
     
                                                            

     
                                      
    
                                             
    
                                                              
     
                                                 

     
                                          
    
                                                                                             
    
                                                                                        
     
                                                   

     
                                       
    
                                              
    
                                                               
     
                                                  

     
                                           
    
                                                                                              
                                                                       
    
                                                                                        
     
                                                                          

     
                                                              
    
                                                                                             
                                                                                             
               
    
                                            
    
                                                                                                   
     
                                                                        

     
                                                                  
    
                                                                                                
                                  
    
                                                                
                                             
                                                                                                   
                            
    
                                                      
     
                                                                         
 

function isKeyPair               (skR                )                    {
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

 
async function KeySchedule(
  suite        ,
  mode        ,
  shared_secret            ,
  info             ,
  psk             ,
  pskId             ,
) {
  info ??= new Uint8Array()
  checkUint8Array(info, 'info')
  psk ??= new Uint8Array()
  checkUint8Array(psk, 'psk')
  pskId ??= new Uint8Array()
  checkUint8Array(pskId, 'pskId')

  const stages = KDFStages(suite.KDF)
  const CombineSecrets = stages === 1 ? CombineSecrets_OneStage : CombineSecrets_TwoStage

  VerifyPSKInputs(psk, pskId)
  return await CombineSecrets(suite, mode, shared_secret, info, psk, pskId)
}

 
function VerifyPSKInputs(psk            , psk_id            ) {
  if (psk.byteLength && psk_id.byteLength) {
    if (psk.byteLength < 32) {
      throw new TypeError('Insufficient PSK length')
    }
    return
  }
  if (!psk.byteLength && !psk_id.byteLength) {
    return
  }
  throw new TypeError('Inconsistent PSK inputs')
}

 
const NotApplicable = () => {
  throw new Error('unreachable')
}

const EXPORT_ONLY = 0xffff
const AES_GCM_P_MAX = 2 ** 36 - 31
const CHACHA20_POLY1305_P_MAX = 2 ** 38 - 64












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

                            
                       
 

                                                                     

                               
                   
                         
 

async function getCachedCryptoKey(
  cache                                          ,
  keyBytes            ,
  init                                           ,
)                     {
  const cached = cache.get(keyBytes)
  if (
    cached &&
    cached.bytes.byteLength === keyBytes.byteLength &&
    cached.bytes.every((byte, index) => byte === keyBytes[index])
  ) {
    return cached.key
  }

  const bytes = slice(keyBytes)
  const entry = { bytes, key: init(bytes) }
  cache.set(keyBytes, entry)
  try {
    return await entry.key
  } catch (cause) {
    if (cache.get(keyBytes) === entry) cache.delete(keyBytes)
    throw cause
  }
}

function HKDF_SHARED()           {
  let emptySalt                       
  async function importKey(            salt              )                     {
    return await subtle(
      (c) => c.importKey('raw', salt, { name: 'HMAC', hash: this.hash }, false, ['sign']),
      this.name,
    )
  }
  const cache = new WeakMap                                 ()
  return {
    stages: 2,
    Derive: NotApplicable,
    async Extract(            salt, ikm) {
      const key =
        salt.byteLength === 0
          ? (emptySalt ??= await importKey.call(this, new ArrayBuffer(this.Nh)))
          : await importKey.call(this, salt                )
      return new Uint8Array(
        await subtle((c) => c.sign('HMAC', key, ikm                ), this.name),
      )
    },
    async Expand(            prk, info, L) {
      if (prk.byteLength < this.Nh) {
        throw new Error('prk.byteLength < this.Nh')
      }
      if (L > 255 * this.Nh) {
        throw new Error('L must be <= 255*Nh')
      }
      const N = Math.ceil(L / this.Nh)
      const key = await getCachedCryptoKey(cache, prk, (bytes) =>
        importKey.call(this, bytes                ),
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

 
 
 

                             
                            
 

async function ShakeDerive(name        , variant        , ikm              , L        ) {
  const bits = L << 3
  const alg = { name: variant, length: bits, outputLength: bits }
  return new Uint8Array(await subtle((c) => c.digest(alg, ikm), name))
}

function SHAKE_SHARED()           {
  return {
    stages: 1,
    async Derive(             labeled_ikm, L        ) {
      return await ShakeDerive(this.name, this.algorithm, labeled_ikm                , L)
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




















export const KDF_TurboSHAKE128             = function ()        {
  return {
    id: 0x0012,
    type: 'KDF',
    name: 'TurboSHAKE128',
    Nh: 32,
    algorithm: 'TurboSHAKE128',
    ...SHAKE_SHARED(),
  }
}




















export const KDF_TurboSHAKE256             = function ()        {
  return {
    id: 0x0013,
    type: 'KDF',
    name: 'TurboSHAKE256',
    Nh: 64,
    algorithm: 'TurboSHAKE256',
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

 
 
 

 
async function DeriveKeyPairBytes(
  DHKEM       ,
  ikm            ,
  label            ,
  context            ,
) {
  if (KDFStages(DHKEM.kdf) === 1) {
    return await LabeledDerive(DHKEM.kdf, DHKEM.suite_id, ikm, label, context, DHKEM.Nsk)
  }

  const dkp_prk = await LabeledExtract(DHKEM.kdf, DHKEM.suite_id, new Uint8Array(), L_dkp_prk, ikm)
  return await LabeledExpand(DHKEM.kdf, DHKEM.suite_id, dkp_prk, label, context, DHKEM.Nsk)
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

 
async function ExtractAndExpand_OneStage(
  DHKEM       ,
  dh            ,
  kem_context            ,
)                      {
  return await LabeledDerive(
    DHKEM.kdf,
    DHKEM.suite_id,
    dh,
    L_shared_secret,
    kem_context,
    DHKEM.Nsecret,
  )
}

 
async function ExtractAndExpand_TwoStage(
  DHKEM       ,
  dh            ,
  kem_context            ,
)                      {
  const eae_prk = await LabeledExtract(DHKEM.kdf, DHKEM.suite_id, new Uint8Array(), L_eae_prk, dh)
  return await LabeledExpand(
    DHKEM.kdf,
    DHKEM.suite_id,
    eae_prk,
    L_shared_secret,
    kem_context,
    DHKEM.Nsecret,
  )
}

 
async function ExtractAndExpand(
  DHKEM       ,
  dh            ,
  kem_context            ,
)                      {
  const Fn = KDFStages(DHKEM.kdf) === 1 ? ExtractAndExpand_OneStage : ExtractAndExpand_TwoStage
  return await Fn(DHKEM, dh, kem_context)
}

 
 
 

function DHKEM_SHARED()           
                                                                      
  {
  return {
    async GenerateKeyPair(             extractable) {
      return (await subtle(
        (c) => c.generateKey(this.algorithm, extractable, ['deriveBits']),
        this.name,
      ))                 
    },
    async SerializePublicKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      return new Uint8Array(await subtle((c) => c.exportKey('raw', key), this.name))
    },
    async DeserializePublicKey(             key) {
      return await subtle(
        (c) => c.importKey('raw', key                , this.algorithm, true, []),
        this.name,
      )
    },
    async SerializePrivateKey(             key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
      const { d } = await subtle((c) => c.exportKey('jwk', key), this.name)
      return b64u(d )
    },
    async Encap(             pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      assertCryptoKey(pkR)

      const ekp = (await this.GenerateKeyPair(false))                 
      const skE = ekp.privateKey
      const pkE = ekp.publicKey

       
       
      const dh = new Uint8Array(
        await subtle(
          (c) => c.deriveBits({ name: skE.algorithm.name, public: pkR }, skE, this.Ndh << 3),
          this.name,
        ),
      )

      const enc = await this.SerializePublicKey(pkE)
      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const shared_secret = await ExtractAndExpand(this, dh, kem_context)
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
          (c) => c.deriveBits({ name: skR.algorithm.name, public: pkE }, skR, this.Ndh << 3),
          this.name,
        ),
      )

      const pkRm = await this.SerializePublicKey(pkR)
      const kem_context = concat(enc, pkRm)
      const shared_secret = await ExtractAndExpand(this, dh, kem_context)
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
  name        ,
  Nsk        ,
  template            ,
  algorithm              ,
  key            ,
  extractable         ,
) {
  const tmpl = slice(template)
  const pkcs8 = new Uint8Array(Nsk + tmpl.byteLength)
  pkcs8.set(tmpl)
  pkcs8.set(key, tmpl.byteLength)
  return await subtle(
    (c) => c.importKey('pkcs8', pkcs8, algorithm, extractable, ['deriveBits']),
    name,
  )
}

 
 
 

                           
               
                 
            
            
                   
                  
                           
             
             
 

async function importKeyNist(
  curve                 ,
  key            ,
  name        ,
  extractable         ,
  includePublicKey         ,
)                                                            {
  const d = OS2IP(key)
  if (d === 0n || d >= curve.order) {
    throw new Error('Invalid scalar')
  }

   
  const pkcs8 = concat(curve.pkcs8, key)
  return await subtle(async (c) => {
    async function fromJwk(jwk            , privateKey            ) {
      privateKey ??= await c.importKey('jwk', jwk, curve.algorithm, extractable, ['deriveBits'])
      delete jwk.d
      return {
        privateKey,
        publicKey: includePublicKey
          ? await c.importKey('jwk', jwk, curve.algorithm, true, [])
          : undefined,
      }
    }

    let privateKey                       
     
    const nativePublicKey = typeof c.getPublicKey === 'function'
    try {
      privateKey = await c.importKey(
        'pkcs8',
        pkcs8                ,
        curve.algorithm,
        nativePublicKey ? extractable : true,
        ['deriveBits'],
      )
      if (nativePublicKey) {
         
         
        const recovered = await c.getPublicKey(privateKey, [])
        return { privateKey, publicKey: includePublicKey ? recovered : undefined }
      }
      const { x, y, d } = await c.exportKey('jwk', privateKey)
      return fromJwk(
        { kty: 'EC', crv: curve.algorithm.namedCurve, x, y, d },
        extractable ? privateKey : undefined,
      )
    } catch (cause) {
       
       
       
       
      if (
        !(cause instanceof DOMException) ||
        (cause.name !== 'DataError' && cause.name !== 'OperationError')
      ) {
        throw cause
      }
    }

    const generator             = {
      kty: 'EC',
      crv: curve.algorithm.namedCurve,
      x: toB64u(bigIntToUint8Array(curve.Gx, curve.Nsk)),
      y: toB64u(bigIntToUint8Array(curve.Gy, curve.Nsk)),
    }
    const jwk = { ...generator, d: toB64u(slice(pkcs8, curve.pkcs8.length)) }
    const signingAlgorithm = { name: 'ECDSA', namedCurve: curve.algorithm.namedCurve }
    const signingKey = privateKey
      ? await c.importKey('pkcs8', pkcs8                , signingAlgorithm, false, ['sign'])
      : await c.importKey('jwk', jwk, signingAlgorithm, false, ['sign'])
    privateKey ??= await c.importKey('jwk', jwk, curve.algorithm, false, ['deriveBits'])

     
     
    const generatorKey = await c.importKey('jwk', generator, curve.algorithm, true, [])
    const x = new Uint8Array(
      await c.deriveBits({ name: 'ECDH', public: generatorKey }, privateKey, curve.Nsk << 3),
    )

     
     
    const message = L_public_key_recovery                
    const signatureAlgorithm = { name: 'ECDSA', hash: 'SHA-256' }
    const signature = await c.sign(signatureAlgorithm, signingKey, message)
    for (const prefix of [0x02, 0x03]) {
      const spki = concat(curve.spki, Uint8Array.of(prefix), x)
      const candidate = await c.importKey('spki', spki                , signingAlgorithm, true, [
        'verify',
      ])
      if (await c.verify(signatureAlgorithm, candidate, signature, message)) {
        const { x, y } = await c.exportKey('jwk', candidate)
        return fromJwk({ kty: 'EC', crv: generator.crv, d: jwk.d, x, y })
      }
    }
    throw new Error('Public key recovery failed')
  }, name)
}

async function DeserializePrivateKeyNist(
                                
  key            ,
  extractable         ,
) {
  return (await importKeyNist(this, key, this.name, extractable, false)).privateKey
}

 
async function DeriveKeyPairNist(
                                
  ikm            ,
  extractable         ,
) {
  let sk = 0n
  let counter = 0
  let candidate            
  while (sk === 0n || sk >= this.order) {
    if (counter > 255) {
      throw new DeriveKeyPairError('Key derivation exceeded maximum iterations')
    }
    candidate = await DeriveKeyPairBytes(this, ikm, L_candidate, I2OSP(counter, 1))
    candidate[0] = candidate[0]  & this.bitmask
    sk = OS2IP(candidate)
    counter = counter + 1
  }

  return GetKeyPairNist(this, candidate , extractable, this.name)
}

async function GetKeyPairNist(
  curveConfig                           ,
  sk            ,
  extractable         ,
  name        ,
) {
  return (await importKeyNist(curveConfig, sk, name, extractable, true))                 
}

 
 
 

 
async function DeriveKeyPairX(             ikm            , extractable         ) {
  const sk = await DeriveKeyPairBytes(this, ikm, L_sk, new Uint8Array())
  return await createKeyPairFromPrivateKey(this, sk, extractable)
}

 
 
 

const P256                  = {
  algorithm: { name: 'ECDH', namedCurve: 'P-256' },
  Npk: 65,
  Nsk: 32,
  order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  bitmask: 0xff,
  pkcs8: /* @__PURE__ */ Uint8Array.of(0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20),  
  spki: /* @__PURE__ */ Uint8Array.of(0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00),  
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
}





















export const KEM_DHKEM_P256_HKDF_SHA256                        = function ()         
                  {
  const id = 0x0010
  const name = 'DHKEM(P-256, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
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
  pkcs8: /* @__PURE__ */ Uint8Array.of(0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x30),  
  spki: /* @__PURE__ */ Uint8Array.of(0x30, 0x46, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x32, 0x00),  
  Gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  Gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
}





















export const KEM_DHKEM_P384_HKDF_SHA384                        = function ()         
                  {
  const id = 0x0011
  const name = 'DHKEM(P-384, HKDF-SHA384)'
  const kdf = KDF_HKDF_SHA384()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
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
  pkcs8: /* @__PURE__ */ Uint8Array.of(0x30, 0x60, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x04, 0x49, 0x30, 0x47, 0x02, 0x01, 0x01, 0x04, 0x42),  
  spki: /* @__PURE__ */ Uint8Array.of(0x30, 0x58, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x44, 0x00),  
  Gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
  Gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
}





















export const KEM_DHKEM_P521_HKDF_SHA512                        = function ()         
                  {
  const id = 0x0012
  const name = 'DHKEM(P-521, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
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

 
 
 





















export const KEM_DHKEM_X25519_HKDF_SHA256                        = function ()           
                   
  {
  const id = 0x0020
  const name = 'DHKEM(X25519, HKDF-SHA256)'
  const kdf = KDF_HKDF_SHA256()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
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





















export const KEM_DHKEM_X448_HKDF_SHA512                        = function ()           
                   
  {
  const id = 0x0021
  const name = 'DHKEM(X448, HKDF-SHA512)'
  const kdf = KDF_HKDF_SHA512()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
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

 
 
 

                                                                              

                                            
                               
                                            
                   
 

function DIRECT_KEM_SHARED()                      {
  return {
    async DeriveKeyPair(                 ikm, extractable) {
      const dk = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        L_DeriveKeyPair,
        new Uint8Array(),
        this.Nsk,
      )

      const privateKey = (await this.DeserializePrivateKey(dk, extractable))             
       
      const usages             = ['encapsulateBits']
      const publicKey = await getPublicKey(this.name, privateKey, usages)

      return { privateKey, publicKey }
    },
    async GenerateKeyPair(                 extractable) {
       
      const usages             = ['encapsulateBits', 'decapsulateBits']
      return (await subtle(
        (c) => c.generateKey(this.algorithm, extractable, usages),
        this.name,
      ))                 
    },
    async SerializePublicKey(                 key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
       
      const format                            = 'raw-public'
      return new Uint8Array(await subtle((c) => c.exportKey(format, key), this.name))
    },
    async DeserializePublicKey(                 key) {
       
      const format                            = 'raw-public'
       
      const usages             = ['encapsulateBits']
      return await subtle(
        (c) => c.importKey(format, key                , this.algorithm, true, usages),
        this.name,
      )
    },
    async SerializePrivateKey(                 key) {
      assertKeyAlgorithm(key, this.algorithm)
      assertCryptoKey(key)
       
      const format                            = 'raw-seed'
      return new Uint8Array(await subtle((c) => c.exportKey(format, key), this.name))
    },
    async DeserializePrivateKey(                 key, extractable) {
       
      const format                            = 'raw-seed'
       
      const usages             = ['decapsulateBits']
      return await subtle(
        (c) => c.importKey(format, key                , this.algorithm, extractable, usages),
        this.name,
      )
    },
    async Encap(                 pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)

      const { sharedKey, ciphertext } = (await subtle(
         
        (c) => c.encapsulateBits(this.algorithm, pkR),
        this.name,
      ))                                                       

      return { shared_secret: new Uint8Array(sharedKey), enc: new Uint8Array(ciphertext) }
    },
    async Decap(                 enc, skR, _pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      return new Uint8Array(
        await subtle(
           
          (c) => c.decapsulateBits(this.algorithm, skR, enc                ),
          this.name,
        ),
      )
    },
  }
}

function createDirectKEM({ id, name, Nsecret, Nenc, Npk, Nsk }           )            {
  const kdf = KDF_SHAKE256()
   
  kdf.name = name
  return {
    id,
    suite_id: concat(L_KEM, I2OSP(id, 2)),
    type: 'KEM',
    name,
    Nsecret,
    Nenc,
    Npk,
    Nsk,
    algorithm: { name },
    kdf,
    ...DIRECT_KEM_SHARED(),
  }
}

 
 
 
























export const KEM_ML_KEM_512                        = function ()            {
  const id = 0x0040
  const name = 'ML-KEM-512'
  const Nsecret = 32
  const Nenc = 768
  const Npk = 800
  const Nsk = 64
  return createDirectKEM({ id, name, Nsecret, Nenc, Npk, Nsk })
}




















export const KEM_ML_KEM_768                        = function ()            {
  const id = 0x0041
  const name = 'ML-KEM-768'
  const Nsecret = 32
  const Nenc = 1088
  const Npk = 1184
  const Nsk = 64
  return createDirectKEM({ id, name, Nsecret, Nenc, Npk, Nsk })
}




















export const KEM_ML_KEM_1024                        = function ()            {
  const id = 0x0042
  const name = 'ML-KEM-1024'
  const Nsecret = 32
  const Nenc = 1568
  const Npk = 1568
  const Nsk = 64
  return createDirectKEM({ id, name, Nsecret, Nenc, Npk, Nsk })
}

                                      
                            
                                               
 

                                            

function AEAD_SHARED(P_MAX        )            {
   
   
   
   
   
  const cache = new WeakMap                                 ()
  async function importKey(                     key            )                     {
    return await subtle(
      (c) =>
        c.importKey(this.keyFormat, key                , this.algorithm, false, [
          'encrypt',
          'decrypt',
        ]),
      this.name,
    )
  }
  return {
    async Seal(                     key, nonce, aad, pt) {
      if (pt.byteLength > P_MAX) {
        throw new RangeError('"pt" exceeds P_MAX')
      }
      const cryptoKey = await getCachedCryptoKey(cache, key, (bytes) => importKey.call(this, bytes))
      return new Uint8Array(
        await subtle(
          (c) =>
            c.encrypt(
              {
                name: this.algorithm,
                iv: nonce                ,
                additionalData: aad                ,
              },
              cryptoKey,
              pt                ,
            ),
          this.name,
        ),
      )
    },
    async Open(                     key, nonce, aad, ct) {
      const cryptoKey = await getCachedCryptoKey(cache, key, (bytes) => importKey.call(this, bytes))
      return new Uint8Array(
        await subtle(
          (c) =>
            c.decrypt(
              {
                name: this.algorithm,
                iv: nonce                ,
                additionalData: aad                ,
              },
              cryptoKey,
              ct                ,
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
    ...AEAD_SHARED(AES_GCM_P_MAX),
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
    ...AEAD_SHARED(AES_GCM_P_MAX),
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
    ...AEAD_SHARED(CHACHA20_POLY1305_P_MAX),
  }
}

 
 
 

 
const InvalidInvocation = (_             ) => {
  if (_ !== priv) {
    throw new Error('invalid invocation')
  }
}
const priv = /* @__PURE__ */ Symbol()
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

function RandomScalarNist(t                         , seed            )             {
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

 
async function expandDecapsKeyG(kem                    , seed            ) {
  const Nout = kem.pq.Nseed + kem.t.Nseed
  const bits = Nout << 3
   
  const algorithm               = { name: 'cSHAKE256', length: bits, outputLength: bits }
  const seed_full = await subtle((c) => c.digest(algorithm, seed                ), kem.name)

  const [seed_PQ, seed_T] = split(kem.pq.Nseed, kem.t.Nseed, new Uint8Array(seed_full))

   
  const format                            = 'raw-seed'
   
  const usages                       = ['decapsulateBits', 'encapsulateBits']
  const dk_PQ = await subtle(
    (c) => c.importKey(format, seed_PQ                , kem.pq.algorithm, true, [usages[0]]),
    kem.name,
  )
  const ek_PQ = await getPublicKey(kem.name, dk_PQ, [usages[1]])

  const sk = kem.t.RandomScalar?.(seed_T) ?? seed_T
  const { privateKey: dk_T, publicKey: ek_T } = await kem.t.GetKeyPair(sk)

  return { ek_PQ, ek_T, dk_PQ, dk_T }
}

 
async function C2PRICombiner(
  kem                    ,
  ss_PQ            ,
  ss_T            ,
  ct_T            ,
  _ek_T           ,
  label            ,
)                      {
  const ek_T = new Uint8Array(await subtle((c) => c.exportKey('raw', _ek_T), kem.name))
  const data = concat(ss_PQ, ss_T, ct_T, ek_T, label)                
  return new Uint8Array(await subtle((c) => c.digest('SHA3-256', data), kem.name))
}

 
async function prepareEncapsG(
  kem                    ,
  ek_PQ           ,
  ek_T           ,
)                                                            {
  const res = (await subtle(
     
    (c) => c.encapsulateBits(kem.pq.algorithm, ek_PQ),
    kem.name,
  ))                                                       
  const ss_PQ = new Uint8Array(res.sharedKey)
  const ct_PQ = new Uint8Array(res.ciphertext)

  const { privateKey: sk_E, publicKey } = (await subtle(
    (c) => c.generateKey(kem.t.algorithm, true, ['deriveBits']),
    kem.name,
  ))                 
  const ct_T = new Uint8Array(await subtle((c) => c.exportKey('raw', publicKey), kem.name))

  const ss_T = new Uint8Array(
    await subtle(
      (c) => c.deriveBits({ name: kem.t.algorithm.name, public: ek_T }, sk_E, kem.t.Nss << 3),
      kem.name,
    ),
  )

  return [ss_PQ, ss_T, ct_PQ, ct_T]
}

 
async function prepareDecapsG(
  kem                    ,
  dk_PQ           ,
  dk_T           ,
  ct_PQ            ,
  ct_T            ,
)                                    {
  const ss_PQ = new Uint8Array(
    await subtle(
       
      (c) => c.decapsulateBits(kem.pq.algorithm, dk_PQ, ct_PQ),
      kem.name,
    ),
  )

  const pub = await subtle(
    (c) => c.importKey('raw', ct_T                , kem.t.algorithm, true, []),
    kem.name,
  )

  const ss_T = new Uint8Array(
    await subtle(
      (c) => c.deriveBits({ name: kem.t.algorithm.name, public: pub }, dk_T, kem.t.Nss << 3),
      kem.name,
    ),
  )

  return [ss_PQ, ss_T]
}

                                                     
                               
                   
                                  
                            
                
                                    
                          
                        
                        
   
               
                                                     
                          
                        
                        
                        
                        
                             
                          
                                    
                     
                                                                 
                           
                                                                                           
   
 

                                                                                          

function COMPOSITE_HYBRID_KEM_SHARED()                      {
  Object.freeze(HybridKey.prototype)
  return {
    async DeriveKeyPair(                          ikm            , extractable) {
      const seed = await LabeledDerive(
        this.kdf,
        this.suite_id,
        ikm,
        L_DeriveKeyPair,
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
    async GenerateKeyPair(                          extractable) {
      return await this.DeriveKeyPair(crypto.getRandomValues(new Uint8Array(32)), extractable)
    },
    async SerializePublicKey(                          key) {
      assertKeyAlgorithm(key, this.algorithm)
      HybridKey.validate(key, true)
       
      const format                            = 'raw-public'
      const ek_PQ = new Uint8Array(
        await subtle((c) => c.exportKey(format, key.getPq(priv)), this.name),
      )
      const ek_T = new Uint8Array(
        await subtle((c) => c.exportKey('raw', key.getT(priv)), this.name),
      )

      return concat(ek_PQ, ek_T)
    },
    async DeserializePublicKey(                          key) {
       
      const format                            = 'raw-public'
       
      const usages             = ['encapsulateBits']
      const pubPq = key.subarray(0, this.pq.Npk)                
      const pubT = key.subarray(this.pq.Npk)                
      const [ek_PQ, ek_T] = await Promise.all([
        subtle((c) => c.importKey(format, pubPq, this.pq.algorithm, true, usages), this.name),
        subtle((c) => c.importKey('raw', pubT, this.t.algorithm, true, []), this.name),
      ])

      return new HybridKey(priv, this.algorithm, 'public', true, ek_PQ, ek_T)
    },
    async SerializePrivateKey(                          key) {
      assertKeyAlgorithm(key, this.algorithm)
      HybridKey.validate(key, true)

      return key.getSeed(priv)
    },
    async DeserializePrivateKey(                          key, extractable) {
      const seed = slice(key)
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

      return privateKey
    },
    async Encap(                          pkR) {
      assertKeyAlgorithm(pkR, this.algorithm)
      HybridKey.validate(pkR)

      const ek_PQ = pkR.getPq(priv)
      const ek_T = pkR.getT(priv)
      const [ss_PQ, ss_T, ct_PQ, ct_T] = await prepareEncapsG(this, ek_PQ, ek_T)
      const ss_H = await C2PRICombiner(this, ss_PQ, ss_T, ct_T, ek_T, this.label)
      const ct_H = concat(ct_PQ, ct_T)

      return { shared_secret: ss_H, enc: ct_H }
    },
    async Decap(                          enc, skR, pkR) {
      assertKeyAlgorithm(skR, this.algorithm)
      HybridKey.validate(skR)

      if (pkR) {
        assertKeyAlgorithm(pkR, this.algorithm)
        HybridKey.validate(pkR)
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

function createCompositeHybridKEM(parameters                          )                     {
  const kdf = KDF_SHAKE256()
   
  kdf.name = parameters.name
  return {
    ...parameters,
    suite_id: concat(L_KEM, I2OSP(parameters.id, 2)),
    type: 'KEM',
    algorithm: { name: parameters.name },
    kdf,
    ...COMPOSITE_HYBRID_KEM_SHARED(),
  }
}

 
 
 


























export const KEM_MLKEM768_X25519             = function ()                                 {
  const id = 0x647a
  const name = 'MLKEM768-X25519'
  const Nsecret = 32
  const Nenc = 1120
  const Npk = 1216
  const Nsk = 32
  const kem = { id, name, Nsecret, Nenc, Npk, Nsk }
   
  if (SubtleCrypto.supports?.('generateKey', name) ?? false) {
    return createDirectKEM(kem)
  }

  const pkcs8 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20)  
  return createCompositeHybridKEM({
    ...kem,
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
  })
}


























export const KEM_MLKEM768_P256             = function ()                                 {
  const id = 0x0050
  const name = 'MLKEM768-P256'
  const Nsecret = 32
  const Nenc = 1153
  const Npk = 1249
  const Nsk = 32
  const kem = { id, name, Nsecret, Nenc, Npk, Nsk }
   
  if (SubtleCrypto.supports?.('generateKey', name) ?? false) {
    return createDirectKEM(kem)
  }

  return createCompositeHybridKEM({
    ...kem,
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
  })
}


























export const KEM_MLKEM1024_P384             = function ()                                 {
  const id = 0x0051
  const name = 'MLKEM1024-P384'
  const Nsecret = 32
  const Nenc = 1665
  const Npk = 1665
  const Nsk = 32
  const kem = { id, name, Nsecret, Nenc, Npk, Nsk }
   
  if (SubtleCrypto.supports?.('generateKey', name) ?? false) {
    return createDirectKEM(kem)
  }

  return createCompositeHybridKEM({
    ...kem,
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
  })
}
