const sodium = require('sodium-universal')
const Keychain = require('keypear')
const { keyPair } = require('hypercore-crypto')

function getKeyChain (kp) {
  return new Keychain(kp)
}

function generateKeyPairFromSeed (seed) {
  const s = typeof seed === 'string' ? Buffer.from(seed, 'hex') : seed

  return keyPair(Keychain.keyPair(s).scalar)
}

function generateEncryptionKeyFromKeyPair (keyPair) {
  const { publicKey, secretKey } = keyPair
  if (!publicKey || !secretKey) throw new Error('Invalid key pair')

  const combinedKeys = Buffer.concat([publicKey, secretKey])
  const hash = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(hash, combinedKeys)

  return hash
}

function generateChildKeyPair (seed, name) {
  if (!name) throw new Error('Name your child!')
  const kp = generateKeyPairFromSeed(seed)
  const kc = getKeyChain(kp)
  return keyPair(kc.get(name).scalar)
}

function decryptSeed (data) {
  const { nonce, ciphertext, salt, password } = data
  const key = deriveKey(password, salt)

  return decryptWithSodium(ciphertext, nonce, key)
}

function encryptSeed (seed, password, salt) {
  const key = deriveKey(password, salt)

  return encryptWithSodium(seed, key)
}

function encryptWithSodium (plaintext, key) {
  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  const plaintextBuffer = Buffer.from(plaintext, 'hex')
  const ciphertext = Buffer.alloc(plaintextBuffer.length + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(ciphertext, plaintextBuffer, nonce, key)

  return { nonce, ciphertext }
}

function decryptWithSodium (ciphertext, nonce, key) {
  const decrypted = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES)
  if (!sodium.crypto_secretbox_open_easy(decrypted, ciphertext, nonce, key)) {
    throw new Error('Decryption failed')
  }
  return decrypted.toString('hex')
}

function deriveKey (password, salt) {
  const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
  const passwordBuffer = Buffer.from(password, 'utf8')

  sodium.crypto_pwhash(
    key,
    passwordBuffer,
    salt,
    Number(process.env.OPSLIMIT || sodium.crypto_pwhash_OPSLIMIT_SENSITIVE),
    Number(process.env.MEMLIMIT || sodium.crypto_pwhash_MEMLIMIT_SENSITIVE),
    sodium.crypto_pwhash_ALG_DEFAULT
  )

  return key
}

module.exports = {
  generateKeyPairFromSeed,
  generateEncryptionKeyFromKeyPair,
  generateChildKeyPair,
  encryptSeed,
  decryptSeed,
  encryptWithSodium,
  decryptWithSodium,
  deriveKey,
  getKeyChain
}
