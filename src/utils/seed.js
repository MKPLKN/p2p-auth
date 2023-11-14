import { BIP32Factory } from 'bip32'
import * as ecc from 'tiny-secp256k1'
import crypto from 'crypto'
import bip39 from 'bip39'
import sodium from 'sodium-universal'
import { keyPair } from 'hypercore-crypto'

let bip32 = null
export function getBip32 () {
  if (bip32) return bip32
  bip32 = BIP32Factory(ecc)
  return bip32
}

export function getPathLastIndex (path) {
  // Split the path into components
  const parts = path.split('/')

  // Get the last component and convert it to a number
  const lastIndex = parseInt(parts[parts.length - 1], 10)

  return { parts, lastIndex }
}

// Validation function for seed
export function validateSeed (seed) {
  // Example: Validate the seed's length and format
  const expectedLength = 64 // Assuming a 32-byte seed represented in hexadecimal
  const hexRegex = /^[0-9a-fA-F]{64}$/ // Regex for 64-character hexadecimal
  return typeof seed === 'string' && seed.length === expectedLength && hexRegex.test(seed)
}

export function validateSeedPhrase (seedPhrase) {
  return bip39.validateMnemonic(seedPhrase)
}

export function isValidPath (path) {
  // Regular expression to match the pattern "m/x'/y/z" where x, y, z are numbers and the apostrophe is optional
  const validPathRegex = /^m(\/\d+'?)*$/

  return validPathRegex.test(path)
}

export function getDerivationPath (index = 0) {
  return `m/0'/1/${index}`
}

export function getNextDerivedPath (paths) {
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

export function increaseDerivationPath (path) {
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

export function generateKeyPairFromSeed (seed) {
  if (typeof seed === 'string') {
    return keyPair(Buffer.from(seed, 'hex'))
  }

  return keyPair(seed)
}

export function generateMasterKeyPairFromMnemonic (mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic')
  }

  // Generate seed from mnemonic
  const seed = bip39.mnemonicToSeedSync(mnemonic)

  // Generate a master key pair from the seed
  return generateKeyPairFromSeed(seed.slice(0, 32)) // Use the first 32 bytes for libsodium
}

export function generateEncryptionKeyFromKeyPair (keyPair) {
  const { publicKey, secretKey } = keyPair

  if (!publicKey || !secretKey) {
    throw new Error('Invalid key pair')
  }

  // Combine the public and private keys
  const combinedKeys = Buffer.concat([publicKey, secretKey])

  // Hash the combined keys
  const hash = crypto.createHash('sha256')
  hash.update(combinedKeys)

  // Use the hash digest as the encryption key
  const encryptionKey = hash.digest() // Returns a Buffer

  return encryptionKey
}

export function generateChildKeyPair (seed, path = "m/0'/1/0") {
  return generateKeyPairFromSeed(
    deriveChildSeed(seed, path)
  )
}

export function generateRandomSeed () {
  // Create a buffer to hold the seed
  const seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)

  // Fill the buffer with random bytes
  sodium.randombytes_buf(seed)

  // Return the seed as a hex string
  return seed.toString('hex')
}

export function deriveChildSeed (seed, path = "m/0'/1/0") {
  const ms = typeof seed === 'string' ? Buffer.from(seed, 'hex') : seed
  const node = getBip32().fromSeed(ms)
  const child = node.derivePath(path)
  return child.privateKey
}

export function seedToMnemonic (seed) {
  // Convert the seed to a Buffer
  const seedBuffer = Buffer.from(seed, 'hex')

  const mnemonic = bip39.entropyToMnemonic(seedBuffer)

  return mnemonic
}

export function mnemonicToSeed (mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase.')
  }

  // Use the bip39 library to convert the mnemonic back to its original entropy
  const entropy = bip39.mnemonicToEntropy(mnemonic)

  // The entropy returned by mnemonicToEntropy is in hexadecimal format
  return entropy
}

export function decryptSeed (iv, encryptedSeed, authTag, password, salt) {
  // Derive a key using PBKDF2 with the password and salt
  const key = crypto.pbkdf2Sync(password, salt.toString('hex'), 100000, 32, 'sha512')

  // Create a decipher
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)

  // Decrypt the seed
  let decrypted = decipher.update(encryptedSeed.toString('hex'), 'hex', 'hex')
  decrypted += decipher.final('hex')

  return decrypted
}

export function encryptSeed (seed, password, salt) {
  // Generate a key using PBKDF2 with the password and salt
  const key = crypto.pbkdf2Sync(password, salt.toString('hex'), 100000, 32, 'sha512')

  // Generate a random IV
  const iv = crypto.randomBytes(16)

  // Initialize an AES cipher in GCM mode
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

  // Encrypt the seed and get the encrypted data
  let encrypted = cipher.update(seed, 'hex', 'hex')
  encrypted += cipher.final('hex')

  // Concatenate the IV and authentication tag with the encrypted data
  return iv.toString('hex') + encrypted + cipher.getAuthTag().toString('hex')
}
