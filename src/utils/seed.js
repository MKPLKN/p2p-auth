const { BIP32Factory } = require('bip32')
const ecc = require('@bitcoinerlab/secp256k1')
const bip39 = require('bip39')
const sodium = require('sodium-universal')
const { keyPair } = require('hypercore-crypto')

let bip32 = null
function getBip32 () {
  if (bip32) return bip32
  bip32 = BIP32Factory(ecc)
  return bip32
}

function getPathLastIndex (path) {
  // Split the path into components
  const parts = path.split('/')

  // Get the last component and convert it to a number
  const lastIndex = parseInt(parts[parts.length - 1], 10)

  return { parts, lastIndex }
}

// Validation function for seed
function validateSeed (seed) {
  // Example: Validate the seed's length and format
  const expectedLength = 64 // Assuming a 32-byte seed represented in hexadecimal
  const hexRegex = /^[0-9a-fA-F]{64}$/ // Regex for 64-character hexadecimal
  return typeof seed === 'string' && seed.length === expectedLength && hexRegex.test(seed)
}

function validateSeedPhrase (seedPhrase) {
  return bip39.validateMnemonic(seedPhrase)
}

function isValidPath (path) {
  // Regular expression to match the pattern "m/x'/y/z" where x, y, z are numbers and the apostrophe is optional
  const validPathRegex = /^m(\/\d+'?)*$/

  return validPathRegex.test(path)
}

function getDerivationPath (index = 0) {
  return `m/0'/1/${index}`
}

function getNextDerivedPath (paths) {
  if (!Array.isArray(paths) || paths.length === 0) {
    return "m/0'/1/0"
  }

  let highestIndex = -1
  paths.forEach(path => {
    const { lastIndex } = getPathLastIndex(path)
    if (!isNaN(lastIndex) && lastIndex > highestIndex) {
      highestIndex = lastIndex
    }
  })

  if (highestIndex === -1) {
    throw new Error('Invalid path format in the array.')
  }

  // Reconstructing the path with the next index
  const base = paths[0].split('/')
  base.pop() // Remove the last component
  return `${base.join('/')}/${highestIndex + 1}`
}

function increaseDerivationPath (path) {
  if (!isValidPath(path)) {
    throw new Error(`Invalid path ${path}`)
  }

  const { parts, lastIndex } = getPathLastIndex(path)

  // Increment the last index
  const incrementedIndex = lastIndex + 1

  // Replace the last part with the incremented index
  parts[parts.length - 1] = incrementedIndex.toString()

  // Reconstruct and return the updated path
  return parts.join('/')
}

function generateKeyPairFromSeed (seed) {
  if (typeof seed === 'string') {
    return keyPair(Buffer.from(seed, 'hex'))
  }

  return keyPair(seed)
}

function generateMasterKeyPairFromMnemonic (mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic')
  }

  // Generate seed from mnemonic
  const seed = bip39.mnemonicToSeedSync(mnemonic)

  // Generate a master key pair from the seed
  return generateKeyPairFromSeed(seed.slice(0, 32)) // Use the first 32 bytes for libsodium
}

function generateEncryptionKeyFromKeyPair (keyPair) {
  const { publicKey, secretKey } = keyPair

  if (!publicKey || !secretKey) {
    throw new Error('Invalid key pair')
  }

  // Combine the public and private keys
  const combinedKeys = Buffer.concat([publicKey, secretKey])

  // Hash the combined keys using sodium-native
  const hash = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(hash, combinedKeys)

  return hash
}

function generateChildKeyPair (seed, path = "m/0'/1/0") {
  return generateKeyPairFromSeed(
    deriveChildSeed(seed, path)
  )
}

function generateRandomSeed () {
  // Create a buffer to hold the seed
  const seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)

  // Fill the buffer with random bytes
  sodium.randombytes_buf(seed)

  // Return the seed as a hex string
  return seed.toString('hex')
}

function deriveChildSeed (seed, path = "m/0'/1/0") {
  const ms = typeof seed === 'string' ? Buffer.from(seed, 'hex') : seed
  const node = getBip32().fromSeed(ms)
  const child = node.derivePath(path)
  return child.privateKey
}

function seedToMnemonic (seed) {
  // Convert the seed to a Buffer
  const seedBuffer = Buffer.from(seed, 'hex')

  const mnemonic = bip39.entropyToMnemonic(seedBuffer)

  return mnemonic
}

function mnemonicToSeed (mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase.')
  }

  // Use the bip39 library to convert the mnemonic back to its original entropy
  const entropy = bip39.mnemonicToEntropy(mnemonic)

  // The entropy returned by mnemonicToEntropy is in hexadecimal format
  return entropy
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
  getBip32,
  getPathLastIndex,
  validateSeed,
  validateSeedPhrase,
  isValidPath,
  getDerivationPath,
  getNextDerivedPath,
  increaseDerivationPath,
  generateKeyPairFromSeed,
  generateMasterKeyPairFromMnemonic,
  generateEncryptionKeyFromKeyPair,
  generateChildKeyPair,
  generateRandomSeed,
  deriveChildSeed,
  seedToMnemonic,
  mnemonicToSeed,
  encryptSeed,
  decryptSeed,
  encryptWithSodium,
  decryptWithSodium,
  deriveKey
}
