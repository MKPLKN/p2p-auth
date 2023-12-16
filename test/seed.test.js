const test = require('brittle')
const sodium = require('sodium-universal')
const { getBip32, getPathLastIndex, getDerivationPath, getNextDerivedPath, increaseDerivationPath, generateKeyPairFromSeed, generateMasterKeyPairFromMnemonic, generateEncryptionKeyFromKeyPair, generateChildKeyPair, generateRandomSeed, encryptSeed, decryptSeed } = require('../src/utils/seed.js')
const { keyPair } = require('hypercore-crypto')
const { createUser } = require('../src/utils/users.js')

async function createUsers () {
  const userA = await createUser({ username: 'testA', password: 'password' })
  const userB = await createUser({ username: 'testB', password: 'password' })

  return { userA, userB }
}

test('getBip32 initializes and returns bip32', async (t) => {
  const bip32Instance = getBip32()

  // Assertions to verify the correct behavior
  t.ok(bip32Instance, 'bip32 instance should be initialized and returned')

  // Assert that the bip32 instance has a 'fromSeed' method
  t.ok(bip32Instance.fromSeed, 'bip32 instance should have a fromSeed method')
  t.is(typeof bip32Instance.fromSeed, 'function', 'fromSeed should be a function')
})

test('getPathLastIndex with valid path', async (t) => {
  const result = getPathLastIndex('m/44/0/0')

  t.alike(result.parts, ['m', '44', '0', '0'], 'Parts should correctly split the path')
  t.is(result.lastIndex, 0, 'Last index should be 0')
})

test('getPathLastIndex with single part path', async (t) => {
  const result = getPathLastIndex('m')

  t.alike(result.parts, ['m'], 'Parts should contain only one element')
  t.ok(isNaN(result.lastIndex), 'Last index should be NaN for non-numeric part')
})

test('getPathLastIndex with empty path', async (t) => {
  const result = getPathLastIndex('')

  t.is(result.parts.length, 1, 'Parts should have one element for empty path')
  t.ok(isNaN(result.lastIndex), 'Last index should be NaN for empty path')
})

test('getPathLastIndex with non-numeric last part', async (t) => {
  const result = getPathLastIndex('m/44/0/x')

  t.alike(result.parts, ['m', '44', '0', 'x'], 'Parts should correctly split the path')
  t.ok(isNaN(result.lastIndex), 'Last index should be NaN for non-numeric last part')
})

// Tests for getDerivationPath
test('getDerivationPath with default index', async (t) => {
  t.is(getDerivationPath(), 'm/0\'/1/0', 'Should return the default path for index 0')
})

test('getDerivationPath with specified index', async (t) => {
  t.is(getDerivationPath(5), 'm/0\'/1/5', 'Should return the path for the specified index')
})

// Tests for getNextDerivedPath
test('getNextDerivedPath with empty array', async (t) => {
  t.is(getNextDerivedPath([]), 'm/0\'/1/0', 'Should return the default path for an empty array')
})

test('getNextDerivedPath with valid paths', async (t) => {
  t.is(getNextDerivedPath(['m/0\'/1/2', 'm/0\'/1/3']), 'm/0\'/1/4', 'Should return the next path in the sequence')
})

test('getNextDerivedPath with invalid paths', async (t) => {
  t.test('throws error for invalid paths', (t) => {
    try {
      getNextDerivedPath(['invalid', 'path'])
      t.fail('Should have thrown an error')
    } catch (error) {
      t.pass('Expected error thrown')
    }
  })
})

// Tests for increaseDerivationPath
test('increaseDerivationPath with valid path', async (t) => {
  t.is(increaseDerivationPath('m/0\'/1/2'), 'm/0\'/1/3', 'Should increment the last index of the path')
})

test('increaseDerivationPath with invalid path', async (t) => {
  t.test('handles invalid path input', (t) => {
    try {
      increaseDerivationPath('invalid/path')
      t.fail('Should have thrown an error')
    } catch (error) {
      t.pass('Expected error thrown')
    }
  })
})

// Tests for generateKeyPairFromSeed
test('generateKeyPairFromSeed with string seed', async (t) => {
  const seed = Buffer.allocUnsafe(32).fill('test')
  const keyPair = generateKeyPairFromSeed(seed)

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

test('generateKeyPairFromSeed with buffer seed', async (t) => {
  const seed = Buffer.allocUnsafe(32).fill('test')
  const keyPair = generateKeyPairFromSeed(seed)

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

// Test with a valid mnemonic
test('generateMasterKeyPairFromMnemonic with valid mnemonic', async (t) => {
  const validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  const keyPair = generateMasterKeyPairFromMnemonic(validMnemonic)

  t.ok(keyPair.publicKey && keyPair.secretKey, 'Should return a key pair with public and secret keys')
  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

// Test with an invalid mnemonic
test('generateMasterKeyPairFromMnemonic with invalid mnemonic', async (t) => {
  const invalidMnemonic = 'invalid mnemonic'

  try {
    generateMasterKeyPairFromMnemonic(invalidMnemonic)
    t.fail('Should have thrown an error or returned an invalid key pair')
  } catch (error) {
    t.pass('Expected error thrown or invalid key pair returned')
  }
})

test('generateEncryptionKeyFromKeyPair', async (t) => {
  const key = keyPair()
  const encryptionKey = generateEncryptionKeyFromKeyPair(key)

  t.ok(encryptionKey, 'Should return an encryption key')
  t.is(encryptionKey.length, 32, 'Encryption key should be 32 bytes long')
  t.alike(encryptionKey, generateEncryptionKeyFromKeyPair(key), 'Should produce the same encryption key for the same key pair')
  t.unlike(encryptionKey, generateEncryptionKeyFromKeyPair(keyPair()), 'Should produce different encryption key for a diff key pair')
})

// Consistency test for the same seed and path
test('generateChildKeyPair generates consistent key pairs for the same seed and path', async (t) => {
  const { userA } = await createUsers()
  const path = "m/0'/1/0" // A specific path

  const childKeyPair1 = generateChildKeyPair(userA.seed, path)
  const childKeyPair2 = generateChildKeyPair(userA.seed, path)

  t.alike(childKeyPair1, childKeyPair2, 'Should generate the same child key pair for the same seed and path')
})

// Test for different seeds
test('generateChildKeyPair generates different key pairs for different seeds', async (t) => {
  const { userA, userB } = await createUsers()
  const path = "m/0'/1/0"

  const childKeyPair1 = generateChildKeyPair(userA.seed, path)
  const childKeyPair2 = generateChildKeyPair(userB.seed, path)

  t.unlike(childKeyPair1, childKeyPair2, 'Should generate different child key pairs for different seeds')
})

// Test for different paths
test('generateChildKeyPair generates different key pairs for different paths', async (t) => {
  const { userA } = await createUsers()
  const path1 = "m/0'/1/0"
  const path2 = "m/0'/1/1"

  const childKeyPair1 = generateChildKeyPair(userA.seed, path1)
  const childKeyPair2 = generateChildKeyPair(userA.seed, path2)

  t.unlike(childKeyPair1, childKeyPair2, 'Should generate different child key pairs for different paths')
})

test('generateRandomSeed generates a seed of correct length', async (t) => {
  const seedHex = generateRandomSeed()
  const seedBytesLength = sodium.crypto_sign_SEEDBYTES
  const expectedLength = seedBytesLength * 2 // Each byte is represented by two hex characters

  t.is(seedHex.length, expectedLength, 'Seed should have the correct length in hex format')
  t.is(typeof seedHex, 'string', 'Seed should have be in string format')
  const hexRegex = /^[0-9a-fA-F]+$/ // Regex for hexadecimal
  t.ok(hexRegex.test(seedHex), 'Seed should be in hexadecimal format')
})

test('decryptSeed correctly decrypts an encrypted seed', async (t) => {
  const seed = '1234567890abcdef1234567890abcdef'
  const password = 'strongpassword'
  const salt = 'salt'

  // Encrypt the seed first
  const encryptedData = encryptSeed(seed, password, salt)
  // Extract iv and authTag from the encrypted data
  const iv = Buffer.from(encryptedData.slice(0, 32), 'hex')
  const encryptedSeed = Buffer.from(encryptedData.slice(32, -32), 'hex')
  const authTag = Buffer.from(encryptedData.slice(-32), 'hex')

  // Decrypt the seed
  const decryptedSeed = decryptSeed(iv, encryptedSeed, authTag, password, salt)

  t.is(decryptedSeed, seed, 'Decrypted seed should match the original seed')
})
